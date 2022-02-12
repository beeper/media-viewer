# beeper-media-viewer - A simple web app that can download, decrypt and display encrypted Matrix media.
# Copyright (C) 2022 Tulir Asokan
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
from __future__ import annotations

import unpaddedbase64
import hashlib
import hmac

from yarl import URL

from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper
from mautrix.types import EventType

from maubot import Plugin, MessageEvent
from maubot.handlers import event


class Config(BaseProxyConfig):
    def do_update(self, helper: ConfigUpdateHelper) -> None:
        helper.copy("media_viewer_url")


class MediaViewerBot(Plugin):
    bmv_url: URL

    async def start(self):
        self.on_external_config_update()

    def on_external_config_update(self) -> None:
        self.config.load_and_update()
        self.bmv_url = URL(self.config["media_viewer_url"])

    @event.on(EventType.ROOM_MESSAGE)
    async def on_message(self, evt: MessageEvent) -> None:
        if evt.sender == self.client.mxid or not evt.content.msgtype.is_media or not evt.content.file:
            return

        key_raw = unpaddedbase64.decode_base64(evt.content.file.key.key)
        key_hash = unpaddedbase64.encode_base64(hashlib.sha256(key_raw).digest())

        req = {
            "iv": evt.content.file.iv,
            "sha256": evt.content.file.hashes["sha256"],
            "url": evt.content.file.url,
            "info": evt.content.info.serialize(),
            "key_sha256": key_hash,
        }
        signature_content = req["url"] + req["sha256"] + req["iv"]
        signature = hmac.new(key_raw, signature_content.encode("utf-8"), hashlib.sha256).digest()
        req["signature"] = unpaddedbase64.encode_base64(signature)
        req["info"]["filename"] = evt.content.body
        # We don't care about thumbnails
        req["info"].pop("thumbnail_file", None)
        req["info"].pop("thumbnail_info", None)
        try:
            resp = await self.http.post(self.bmv_url / "create", json=req)
            resp_data = await resp.json()
            if resp.status >= 400 and "error" in resp_data:
                raise Exception(resp_data["error"])
            file_id = resp_data["file_id"]
        except Exception as err:
            self.log.warning(f"Failed to create media viewer URL: {type(err).__name__}: {err}")
            await evt.reply("Error requesting media viewer URL, see logs for details")
            return
        await evt.reply(str((self.bmv_url / file_id).with_fragment(evt.content.file.key.key)))

    @classmethod
    def get_config_class(cls) -> type[BaseProxyConfig]:
        return Config
