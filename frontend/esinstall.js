const {install, printStats} = require("esinstall")

install(
	[{
		specifier: "htm/preact",
		named: ["html", "render", "Component"],
	}, {
		specifier: "matrix-encrypt-attachment",
		named: ["decryptAttachment", "decodeBase64", "encodeBase64"],
	}],
	{
		dest: "./lib",
		sourceMap: false,
		treeshake: true,
		verbose: true,
	}
).then(data => {
	const oldPrefix = "web_modules/"
	const newPrefix = "lib/"
	const spaces = " ".repeat(oldPrefix.length - newPrefix.length)
	console.log("Installation complete")
	console.log(printStats(data.stats).replace(oldPrefix, newPrefix + spaces))
})
