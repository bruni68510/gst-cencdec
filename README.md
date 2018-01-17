This package provides an example GStreamer element that implements
DASH Common Encryption (ISO/IEC23001-7 Information technology — MPEG 
systems technologies — Part 7: Common encryption in ISO base media 
file format files).

It takes video or audio (of type "application/x-cenc")
from qtdemux and performs the AES-CTR decryption and outputs the decrypted
content on a source pad.

This version handle widevine test encrypted contents.See https://www.bento4.com/developers/dash/encryption-and-drm/ widevine section.

Requirements
------------
*    gstreamer 1.6
*    libwidevinecwrapperlib (sources are private for now).

Usage
-----
The decryptor implements the interface to the widevine DRM interfacing the widevine DRM library.
