# ShoC2
www.ShadowStackRe.com

ShoC2 will analyze a binary for all IPv4 addresses.  For each IPv4 address found, ShoC2 will retrieve host information about the address from Shodan.


## Version
- Linux 1.0
- Windows 1.0


## Usage
**Note: put the Shodan API key in a file called shodan.key**
```
./ShoC2 <path to sample file>
```


## Output format
The Shodan results are printed to STDOUT in the following format:
```
---------- RECORD START: <IP> ----------
<Shodan Results in JSON format>
---------- RECORD END ------------
```


## Features
- Analyze a binary or text file
- Find all IPv4 addresses
- Get host information about an IPv4 address using the provided Shodan API key


## Shodan API
 https://developer.shodan.io/api


## Changelog
- August 19th 2023:
    - Initial release


## License
MIT License
Copyright 2023 ShadowStackRe.com

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.