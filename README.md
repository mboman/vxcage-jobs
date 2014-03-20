vxcage-jobs
===========

Asyncronious workers for vxcage (mongodb-flavour) that performs metadata
extraction and analysis.

job-basename.py
    Removes all path information for the sample name.

job-exif.py
    Extracts EXIF-data from the file using the exiftool.

job-filemagic.py
    Extracts the file magic identifyers.

job-hashes.py
    Hashes the file into several popular hash formats (sha1, sha256,
    sha512, ssdeep). MD5 hashing is naitive to MongoDB/GridFS. pydeep
    is installed seperatly.

job-pdf.py
    Extract PDF metadata from PDF-files. Uses PDFiD by Didier Stevens.

job-pe.py
    Extracts PE header information from executables, including PEiD. Uses
    PEFile / PEUtils from Ero Carrera (included).

job-strings.py
    Extracts all (unique) strings from a binary.

job-virustotal.py
    Performs a VirusTotal lookup of the analyzed sample. Uses the requests
    library (installed seperatly)

job-yara.py
    Analyze the sample using YARA (http://plusvic.github.io/yara/). Yara
    and yara-python is installed seperatly.
