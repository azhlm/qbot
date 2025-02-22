## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Introduction
This repository contains code used for the Qakbot (2020) analysis. The main functionalities include creating API structures, decompressing data, and decrypting strings.

## Features
- **Structure Creation**: Finds, parses and creates API structures from binary data.
- **Data Decompression**: Decompresses payload using the `brieflz` library.
- **String Decryption**: Finds and decrypts strings using a specific XOR-based algorithm.

## Usage
### String Decryption
The `str_decrypt.py` script automatically decrypts all the strings using an XOR-based algorithm. 

You can also manually decrypt strings. Here's an example of how to use it:

```python
# Import the script to use decrypt function
import str_decrypt

# Example function call
decrypted_string = str_decrypt.strdec(offset)
```

### API structure Creation
The `create_struct.py` script is used to create and automatically analyze API structures from binary data, based on the result of running `str_decrypt.py`. 

### Data Decompression
The `decompress.py` script decompresses RC4 decrypted data using the `brieflz` library. To use this script, run the following command:

```bash
python decompress.py <compressed_file>
```

## Contributing
Contributions are welcome! Please fork the repository and create a pull request.

## License
This project is licensed under the MIT License.

---