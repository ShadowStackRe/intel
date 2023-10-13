/*
MIT License
Copyright 2023 ShadowStackRe.com
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

rule goodday {
meta:
      description = "rule to detect Goodday Ransomware"
      author = "ShadowStackRe.com"
      date = "2023-10-12"
      Rule_Version = "v1"
      malware_type = "ransomware"
      malware_family = "Gooday"
      License = "MIT License, https://opensource.org/license/mit/"

strings:
    $strFile_A = "crYptA" ascii wide    
    $strFile_B = "crYptB" ascii wide
    $strFile_C = "crYptC" ascii wide
    $strFile_D = "crYptD" ascii wide
    $strFile_E = "crYptE" ascii wide
    $strFile_F = "crYptF" ascii wide
    $strTorInfo = "Download & Install TOR browser" ascii wide
    $strReadmeNote = "readme_for_unlock.txt" ascii wide
    $strAttention = "ATTENTION" ascii wide
    $strHacked = "Your network is hacked and files are encrypted." ascii wide

condition:
    all of them
}