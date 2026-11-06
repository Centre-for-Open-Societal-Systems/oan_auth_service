"""A delegated user's picture, from the identity provider's `picture` claim onto `User.user_image`.

eSignet sends the photo as base64 text, not a URL. The claim is the identity
provider's data, but it is still untrusted bytes: it is decoded under a size
cap, accepted only if its content is really a JPEG or PNG, and re-encoded so no
metadata survives and a file Pillow cannot parse is refused. A URL is never
fetched. The file is private, since it is a person's face.
"""

import base64
import hashlib
import io

import frappe

MAX_BYTES = 2 * 1024 * 1024
# A 2 MB JPEG can decode to far more pixels than its size suggests.
MAX_PIXELS = 25_000_000
_EXTENSION_FOR_MIME = {"image/jpeg": "jpg", "image/png": "png"}


def decode_picture(claim) -> tuple[bytes, str] | None:
	"""`(clean image bytes, extension)` for a base64 `claim` holding a JPEG or PNG, else None."""
	if not isinstance(claim, str):
		return None
	data = claim.strip()
	if data.startswith("data:"):
		head, _sep, data = data.partition(",")
		if ";base64" not in head:
			return None
	if not data or len(data) > MAX_BYTES * 4 // 3 + 4:
		return None
	# eSignet may send the URL-safe alphabet without padding.
	data = data.replace("-", "+").replace("_", "/")
	data += "=" * (-len(data) % 4)
	try:
		raw = base64.b64decode(data, validate=True)
	except ValueError:
		return None
	if not raw or len(raw) > MAX_BYTES:
		return None

	import filetype
	from PIL import Image

	kind = filetype.guess(raw)
	extension = _EXTENSION_FOR_MIME.get(kind.mime) if kind else None
	if not extension:
		return None
	try:
		image = Image.open(io.BytesIO(raw))
		if image.width * image.height > MAX_PIXELS:
			return None
		image.load()
		clean = io.BytesIO()
		# Saving without `exif` or `pnginfo` drops every metadata block, GPS included.
		image.save(clean, format=image.format)
	except Exception:
		return None
	return clean.getvalue(), extension


def sync_user_image(user: str, claim) -> bool:
	"""Make the `picture` claim the `User`'s image. Returns whether it changed.

	The file is named after its content, so an unchanged picture is recognised and
	not saved again, and the previous one is removed when it is replaced.
	"""
	decoded = decode_picture(claim)
	if not decoded:
		return False
	content, extension = decoded
	file_name = f"{hashlib.sha256(content).hexdigest()[:32]}.{extension}"

	current = frappe.db.get_value("User", user, "user_image")
	if current and current.endswith(f"/{file_name}"):
		return False
	if current:
		previous = frappe.db.get_value(
			"File",
			{
				"file_url": current,
				"attached_to_doctype": "User",
				"attached_to_name": user,
				"attached_to_field": "user_image",
			},
		)
		if previous:
			frappe.delete_doc("File", previous, ignore_permissions=True, force=True)

	file_doc = frappe.get_doc(
		{
			"doctype": "File",
			"file_name": file_name,
			"content": content,
			"is_private": 1,
			"attached_to_doctype": "User",
			"attached_to_name": user,
			"attached_to_field": "user_image",
		}
	).insert(ignore_permissions=True)
	frappe.db.set_value("User", user, "user_image", file_doc.file_url, update_modified=False)
	return True
