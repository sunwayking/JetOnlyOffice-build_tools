#!/usr/bin/env python3

from pathlib import Path
import sys
import zipfile


FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

MIMETYPES = {
  "odt": "application/vnd.oasis.opendocument.text",
  "ods": "application/vnd.oasis.opendocument.spreadsheet",
  "odp": "application/vnd.oasis.opendocument.presentation",
}

META_XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" office:version="1.3">
 <office:meta><meta:generator>JetOnlyOffice QA corpus</meta:generator></office:meta>
</office:document-meta>
'''

STYLES_XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<office:document-styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" office:version="1.3">
 <office:styles/><office:automatic-styles/><office:master-styles/>
</office:document-styles>
'''

ODT_CONTENT = '''<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" office:version="1.3">
 <office:body><office:text>
  <text:h text:outline-level="1">JetOnlyOffice Mobile QA</text:h>
  <text:p>English text, numbers 12345, and CJK input: 中文输入测试.</text:p>
  <table:table table:name="Command Matrix">
   <table:table-row><table:table-cell office:value-type="string"><text:p>Command</text:p></table:table-cell><table:table-cell office:value-type="string"><text:p>Expected</text:p></table:table-cell></table:table-row>
   <table:table-row><table:table-cell office:value-type="string"><text:p>Bold</text:p></table:table-cell><table:table-cell office:value-type="string"><text:p>Editable</text:p></table:table-cell></table:table-row>
  </table:table>
 </office:text></office:body>
</office:document-content>
'''.encode("utf-8")

ODS_CONTENT = b'''<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" office:version="1.3">
 <office:body><office:spreadsheet><table:table table:name="Mobile QA">
  <table:table-row><table:table-cell office:value-type="string"><text:p>Item</text:p></table:table-cell><table:table-cell office:value-type="string"><text:p>Value</text:p></table:table-cell></table:table-row>
  <table:table-row><table:table-cell office:value-type="string"><text:p>Alpha</text:p></table:table-cell><table:table-cell office:value-type="float" office:value="10"><text:p>10</text:p></table:table-cell></table:table-row>
  <table:table-row><table:table-cell office:value-type="string"><text:p>Beta</text:p></table:table-cell><table:table-cell office:value-type="float" office:value="20"><text:p>20</text:p></table:table-cell></table:table-row>
  <table:table-row><table:table-cell office:value-type="string"><text:p>Total</text:p></table:table-cell><table:table-cell table:formula="of:=SUM([.B2:.B3])" office:value-type="float" office:value="30"><text:p>30</text:p></table:table-cell></table:table-row>
 </table:table></office:spreadsheet></office:body>
</office:document-content>
'''

ODP_CONTENT = b'''<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" office:version="1.3">
 <office:body><office:presentation><draw:page draw:name="page1">
  <draw:frame presentation:class="title" svg:x="1cm" svg:y="1cm" svg:width="23cm" svg:height="2cm"><draw:text-box><text:p>JetOnlyOffice Mobile QA</text:p></draw:text-box></draw:frame>
  <draw:frame presentation:class="outline" svg:x="1cm" svg:y="4cm" svg:width="23cm" svg:height="10cm"><draw:text-box><text:p>Touch, edit, save, reopen</text:p></draw:text-box></draw:frame>
 </draw:page></office:presentation></office:body>
</office:document-content>
'''

CONTENT = {"odt": ODT_CONTENT, "ods": ODS_CONTENT, "odp": ODP_CONTENT}


def zip_info(name, compression):
  info = zipfile.ZipInfo(name, FIXED_TIMESTAMP)
  info.compress_type = compression
  info.create_system = 0
  info.external_attr = 0
  return info


def manifest_xml(media_type):
  return f'''<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">
 <manifest:file-entry manifest:full-path="/" manifest:media-type="{media_type}"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
 <manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml"/>
 <manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/>
</manifest:manifest>
'''.encode("utf-8")


def build_document(path, extension):
  media_type = MIMETYPES[extension]
  with zipfile.ZipFile(path, "w") as archive:
    archive.writestr(zip_info("mimetype", zipfile.ZIP_STORED), media_type.encode("ascii"))
    archive.writestr(zip_info("content.xml", zipfile.ZIP_DEFLATED), CONTENT[extension])
    archive.writestr(zip_info("styles.xml", zipfile.ZIP_DEFLATED), STYLES_XML)
    archive.writestr(zip_info("meta.xml", zipfile.ZIP_DEFLATED), META_XML)
    archive.writestr(zip_info("META-INF/manifest.xml", zipfile.ZIP_DEFLATED), manifest_xml(media_type))


def main(argv):
  if len(argv) != 2:
    print("usage: build_odf_corpus.py <output-directory>", file=sys.stderr)
    return 2
  output = Path(argv[1])
  output.mkdir(parents=True, exist_ok=True)
  for extension in sorted(MIMETYPES):
    build_document(output / f"basic.{extension}", extension)
  return 0


if __name__ == "__main__":
  sys.exit(main(sys.argv))
