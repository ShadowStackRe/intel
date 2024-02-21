/*
MIT License
Copyright 2024 ShadowStackRe.com
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
rule RansomHouse {
    meta:
        description = "rule to detect RansomHouse"
        author = "ShadowStackRe.com"
        date = "2024-02-20"
        Rule_Version = "v1"
        malware_type = "ransomware"
        malware_family = "RansomHouse"
        License = "MIT License, https://opensource.org/license/mit/"
    strings:
            $strFileExt = ".emario"
            $strRestore = "How To Restore Your Files.txt"
            $strEncrypted = "/path/to/be/encrypted"
            $strCrypted = "Crypted:"
    condition:
            filesize < 100KB and all of ($str*)
}