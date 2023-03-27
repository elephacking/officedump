# officedump

The `officedump` program is a command-line tool for checking running instances of Microsoft Excel and Word, and dump all potential document passwords from their process memory. It accepts various options for controlling its behavior.

## Usage

To run the `officedump` program, open a command prompt or terminal and navigate to the directory where the program is saved. Then, run the program with the desired options:

```
officedump [options]
```

The following options are available:

- `-h`: Displays a help message with usage instructions.
- `-e`: Checks for running instances of Microsoft Excel, auto retreive their process IDs (PIDs) and dump password.
- `-w`: Checks for running instances of Microsoft Word, auto retreive their PIDs and dump password.
- `-ep <pid>`: Dumps the password from memory of the Excel instance with the specified PID to a file. Requires the `-e` option to be specified as well.
- `-wp <pid>`: Dumps the password from memory of the Word instance with the specified PID to a file. Requires the `-w` option to be specified as well.

## Examples

To check for running instances of Excel and Word and dump all potential document passwords:

```
officedump / officedump -e -w
```

To dump from the Excel instance with PID 1234:
```
officedump -e -ep 1234
```

To dump from the Word instance with PID 5678:
```
officedump -w -wp 5678
```

## Compile

To compile, run the `make` command.

## Requirements

The `officedump` program requires a Windows operating system with Microsoft Excel and/or Word installed. It has been tested on Windows 10 with Microsoft Office 365.

## License

The `officedump` program is licensed under the MIT License. See the `LICENSE` file for details.
