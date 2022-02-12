// beeper-media-viewer - A simple web app that can download, decrypt and display encrypted Matrix media.
// Copyright (C) 2022 Tulir Asokan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
import { Component, html, render } from "../lib/htm/preact.js"
import { decodeBase64, decryptAttachment, encodeBase64 } from "../lib/matrix-encrypt-attachment.js"

class CaughtError extends Error {}

class App extends Component {
	constructor(props) {
		super(props)
		this.state = {
			error: "",
			status: "",
			progress: -1,
			blobURL: null,
			fileMeta: null,
		}
		this.saveLinkRef = null
		this.key = {
			kty: "oct",
			key_ops: ["encrypt", "decrypt"],
			alg: "A256CTR",
			k: window.location.hash.replace("#", ""),
			ext: true,
		}
		try {
			this.decodedKey = decodeBase64(this.key.k.replaceAll("-", "+").replaceAll("_", "/"))
		} catch (err) {
			console.error(err)
			this.state.error = "Invalid decryption key"
		}
	}

	async generateFileMetaSignature(meta) {
		const key = await crypto.subtle.importKey("raw", this.decodedKey.buffer, {
			name: "HMAC",
			hash: "SHA-256",
		}, true, ["sign"])
		const msg = new TextEncoder().encode(meta.url + meta.sha256 + meta.iv)
		const sig = await crypto.subtle.sign("HMAC", key, msg)
		return encodeBase64(new Uint8Array(sig))
	}

	async downloadFileMeta() {
		if (!this.key.k) {
			throw new CaughtError("Invalid URL: missing decryption key")
		}
		this.setState({ status: "Fetching file metadata" })
		const keyHashRaw = await crypto.subtle.digest("SHA-256", this.decodedKey.buffer)
		const keyHashString = encodeBase64(new Uint8Array(keyHashRaw))
		let fileMetaResp, fileMeta
		try {
			const metaURL = new URL(window.location)
			metaURL.hash = ""
			metaURL.pathname += "/metadata.json"
			console.log("Downloading metadata from", metaURL, "with key hash", keyHashString)
			fileMetaResp = await fetch(metaURL.toString(), {
				headers: { Authorization: `X-Key-Hash ${keyHashString}` },
			})
			fileMeta = await fileMetaResp.json()
		} catch (err) {
			console.error("Error fetching file metadata:", err)
			throw new CaughtError(`Error fetching file metadata: ${err}`)
		}
		if (fileMetaResp.status >= 400) {
			throw new CaughtError(fileMeta?.message ?? `Failed to fetch file metadata: HTTP ${fileMetaResp.status}`)
		}
		const sig = await this.generateFileMetaSignature(fileMeta)
		if (sig !== fileMeta.signature) {
			console.log("Mismatching metadata signature. Expected:", sig, "- got:", fileMeta.signature)
			throw new CaughtError("Mismatching signature in file metadata")
		}
		return fileMeta
	}

	async downloadFile(fileMeta) {
		this.setState({ status: "Downloading file" })
		const mediaID = fileMeta.url.slice("mxc://".length)
		const url = `${fileMeta.homeserver_url}/_matrix/media/v3/download/${mediaID}`
		let fileResp
		console.log("Downloading file from", url)
		try {
			fileResp = await fetch(url)
		} catch (err) {
			throw new CaughtError(`Error downloading file: ${err}`)
		}
		if (fileResp.status >= 400) {
			let respErrData
			try {
				respErrData = await fileResp.json()
			} catch (err) {}
			if (respErrData?.errcode) {
				throw new CaughtError(`Server returned error: ${respErrData.errcode}: ${respErrData.error}`)
			}
			throw new CaughtError(`Error downloading file: HTTP status ${fileResp.status}`)
		}
		const reader = fileResp.body.getReader()
		const contentLength = +fileResp.headers.get("Content-Length") || fileMeta.info.size

		let receivedLength = 0
		const chunks = []
		while (true) {
			const { done, value } = await reader.read()
			if (done) {
				break
			}
			console.debug("Got", value.length, "bytes of the file")
			chunks.push(value)
			receivedLength += value.length
			if (contentLength) {
				this.setState({ progress: (receivedLength / contentLength) * 100 })
			}
		}
		console.log("File download complete with", receivedLength, "bytes")
		this.setState({ progress: 100 })

		return new Blob(chunks)
	}

	async decryptFile(blob, fileMeta) {
		this.setState({ status: "Decrypting file" })
		console.log("Decrypting file...")
		let decrypted
		try {
			decrypted = await decryptAttachment(await blob.arrayBuffer(), {
				key: this.key,
				iv: fileMeta.iv,
				v: "v2",
				hashes: {
					sha256: fileMeta.sha256,
				},
			})
		} catch (err) {
			console.error("Failed to decrypt file:", err)
			throw new CaughtError(`Error decrypting file: ${err.message}`)
		}
		console.log("Decryption complete")
		return URL.createObjectURL(new Blob([decrypted], { type: fileMeta.info?.mimetype }))
	}

	catchError(err) {
		if (err instanceof CaughtError) {
			this.setState({ error: err.message })
		} else {
			console.error("Uncaught error:", err)
			this.setState({ error: `Unknown error: ${err}` })
		}
	}

	componentDidMount() {
		this.downloadFileMeta()
			.then(fileMeta => this.setState({ fileMeta }))
			.catch(err => this.catchError(err))
	}

	downloadAndDecryptFile(evt) {
		if (evt) {
			evt.stopPropagation()
		}
		if (this.state.loading || !this.state.fileMeta) {
			return
		} else if (this.state.progress === 100 && !window.confirm("Re-download file?")) {
			return
		}
		this.setState({ error: "", loading: true, progress: 0 })
		const fileMeta = this.state.fileMeta
		this.downloadFile(fileMeta)
			.then(blob => this.decryptFile(blob, fileMeta))
			.then(blobURL => this.setState({
				progress: 100,
				loading: false,
				status: "Done",
				fileMeta,
				blobURL,
			}, () => this.autoDownloadIfFile()))
			.catch(err => this.catchError(err))
	}

	autoDownloadIfFile() {
		if (this.state.blobURL && this.saveLinkRef && this.getFileClass() === "file") {
			this.saveLinkRef.click()
		}
	}

	getFileClass() {
		const mimePrefix = this.state.fileMeta?.info?.mimetype?.split("/")[0]
		switch (mimePrefix) {
			case "image":
			case "audio":
			case "video":
				return mimePrefix
			default:
				return "file"
		}
	}

	getFileSize() {
		const round2 = val => Math.round(val * 100) / 100
		if (!this.state.fileMeta) {
			if (this.state.error) {
				return null
			}
			return "0 bytes"
		} else if (!this.state.fileMeta.info?.size) {
			return "unknown size"
		}
		let size = this.state.fileMeta?.info?.size
		if (size < 1000) {
			return `${size} bytes`
		} else if (size < 1000 ** 2) {
			return `${round2(size / 1000)} KB`
		} else if (size < 1000 ** 3) {
			return `${round2(size / 1000 ** 2)} MB`
		} else {
			return `${round2(size / 1000 ** 3)} GB`
		}
	}

	getFileName() {
		if (!this.state.fileMeta) {
			if (this.state.error) {
				return "Error"
			}
			return "Loading..."
		}
		return this.state.fileMeta.info?.filename || `unnamed ${this.getFileClass()}`
	}

	downloadOrSave() {
		if (this.state.blobURL && this.saveLinkRef) {
			this.saveLinkRef.click()
		} else {
			this.downloadAndDecryptFile()
		}
	}

	render() {
		return html`
			<main class=${this.state.error ? "has-error" : ""}>
				<header>
					<img class="wordmark" alt="" src="res/wordmark.svg"/>
				</header>
				<section class="download ${this.state.blobURL ? "loaded" : ""}" onClick=${() => this.downloadOrSave()}>
					<div class="file-metadata">
						<div class="file-type-icon">
							<img src="res/${this.getFileClass()}.svg" alt=""/>
						</div>
						<div class="file-name-and-size">
							<div class="file-name" title=${this.getFileName()}>${this.getFileName()}</div>
							<div class="file-size">${this.getFileSize()}</div>
						</div>
					</div>
					<${SaveButton}
						fileMeta=${this.state.fileMeta}
						blobURL=${this.state.blobURL}
						anchorRef=${ref => this.saveLinkRef = ref}
					>
						<img src="res/save.svg" alt="Save" class="save-icon"/>
					</SaveButton>
					<${DownloadButton}
						onClick=${(evt) => this.downloadAndDecryptFile(evt)}
						progress=${this.state.progress}
					/>
				</section>
				${this.state.error && html`
					<section class="error">
						<div>
							${this.state.error}
						</div>
					</section>
				`}
				<section class="file">
					<${ObjectViewer} blobURL=${this.state.blobURL} fileMeta=${this.state.fileMeta}/>
				</section>
			</main>
		`
	}
}

const ObjectViewer = ({ blobURL, fileMeta }) => {
	if (!blobURL || !fileMeta) {
		return null
	}

	const info = fileMeta.info
	if (info.mimetype.startsWith("image/")) {
		return html`
			<img src="${blobURL}" alt="${info.filename || "image"}" width=${info.w} height=${info.h}/>
		`
	} else if (info.mimetype.startsWith("video/")) {
		return html`
			<video controls src="${blobURL}" width=${info.w} height=${info.h}/>
		`
	} else if (info.mimetype.startsWith("audio/")) {
		return html`
			<audio controls src="${blobURL}"/>
		`
	} else {
		return html`
			<div>
				<p>This type of file can't be displayed inline.</p>
				<${SaveButton} blobURL=${blobURL} fileMeta=${fileMeta}>
					Save to disk
				</SaveButton>
			</div>
		`
	}
}

const SaveButton = ({ blobURL, fileMeta, anchorRef, children }) => {
	return html`
		<a target="_blank"
		   download=${fileMeta ? (fileMeta.info?.filename || "") : undefined}
		   href="${blobURL}"
		   class="save-button"
		   title="Save file to disk"
		   onClick=${evt => evt.stopPropagation()}
		   ref=${anchorRef}
		>
			${children}
		</a>
	`
}

const DownloadButton = ({ onClick, progress }) => {
	if (progress < 0) {
		progress = 0
	} else if (progress >= 100) {
		progress = 100
	} else {
		progress = 12 + (progress / 100) * 72
	}
	return html`
		<div role="button" class="download-button" onClick=${onClick} title="Download and decrypt file">
			<img src="res/download.svg" alt="Download and decrypt file" class="bottom"/>
			<img src="res/download.svg" alt="" class="overlay" style="clip-path: inset(${progress}% 0 0)"/>
		</div>
	`
}

render(html`
	<${App}/>
`, document.body)
