import sys
import linecache
from os import environ
from pathlib import Path

__pwd = Path(environ["PWD"])


def __byteStr2HexStr(byteStr):
    assert type(byteStr) is bytes, "byteStr is not a byte string, got " + str(type(byteStr))
    return ''.join([str.format("{:02X}", ord(bytes([x]))) for x in byteStr]).strip()


def __detailed_trace(ex_type, ex_value, ex_tb):
    max_hex_line_len = 35
    result = []
    result.append(" EXCEPTION {:s}: {:s}".format(str(ex_type), str(ex_value)))
    result.append(" Extended stacktrace follows (most recent call last)")
    skipLocals = True
    while ex_tb:
        frame = ex_tb.tb_frame
        sourceFileName = frame.f_code.co_filename
        try: # To prevent the cases where the file does not belong to the program/project code
            sourceFileLocation = Path(sourceFileName).absolute().relative_to(__pwd)
        except ValueError:
            sourceFileLocation = Path(sourceFileName)

        if "self" in frame.f_locals:
            location = "{:s}.{:s}".format(frame.f_locals["self"].__class__.__name__, frame.f_code.co_name)
        else:
            location = frame.f_code.co_name
        result.append("###")
        result.append(
            "File \"{:s}\", line {:d}, in {:s}".format(
                str(sourceFileLocation), ex_tb.tb_lineno, str(location)
            )
        )
        result.append("Source code:")
        result.append("    " + linecache.getline(sourceFileName, ex_tb.tb_lineno).strip())
        if not skipLocals:
            names = set()
            names.update(getattr(frame.f_code, "co_varnames", ()))
            names.update(getattr(frame.f_code, "co_names", ()))
            names.update(getattr(frame.f_code, "co_cellvars", ()))
            names.update(getattr(frame.f_code, "co_freevars", ()))
            result.append("Local values:")
            for name in sorted(names):
                if name in frame.f_locals:
                    value = frame.f_locals[name]
                    value_str = str(value)
                    if isinstance(value, (bytearray, bytes)):
                        value_lst = list((__byteStr2HexStr(value[i:i + max_hex_line_len]) for i in
                                          range(0, len(value), max_hex_line_len)))
                        result.append("    self.{:s}: {:s}".format(name, value_lst[0]))
                        for line in value_lst[1:]:
                            result.append("               {:s}".format(line))
                    elif (len(value_str) == 0) and (not isinstance(value, str)):
                        value_str = repr(value)
                        result.append("    self.{:s} = {:s}".format(name, value_str))

                    if name == "self":
                        try:  # print the local variables of the class instance
                            for name, value in sorted(vars(value).items()):
                                value_str = str(value)
                                if isinstance(value, (bytearray, bytes)):
                                    value_lst = list((__byteStr2HexStr(value[i:i + max_hex_line_len]) for i in
                                                      range(0, len(value), max_hex_line_len)))
                                    result.append("        self.{:s}: {:s}".format(name, value_lst[0]))
                                    for line in value_lst[1:]:
                                        result.append("                   {:s}".format(line))
                                elif (len(value_str) == 0) and (not isinstance(value, str)):
                                    value_str = repr(value)
                                    result.append("        self.{:s} = {:s}".format(name, value_str))

                        except TypeError:
                            pass
        skipLocals = False
        ex_tb = ex_tb.tb_next

    max_len = len(max(result, key=(lambda line: len(line))))
    for i in range(0, len(result)):
        if result[i] == "###":
            result[i] = "-" * max_len
    result.insert(0, "-" * max_len)
    result.append("-" * max_len)
    result.append(" EXCEPTION {:s}: {:s}".format(str(ex_type), str(ex_value)))
    result.append("-" * max_len)
    return result


def custom_logging_callback(logBook, level, ex_type, ex_value, ex_tb):
    result = __detailed_trace(ex_type, ex_value, ex_tb)
    result = ["\n"] + result
    logBook.log(level, "\n".join(result))

    if ex_type is AssertionError:
        sys.exit("Assertion Failure: {:s}".format(str(ex_value)))


def logger_module_name(file):
    # To prevent the cases where the file does not belong to the program/project code
    # It also prevent the cases where PYTHONPATH is not defined and weird things happen to the file locations
    try:
        return str(Path(file).relative_to(__pwd)).replace(str(Path(file).suffix), "")
    except ValueError:
        return str(Path(file)).replace(str(Path(file).suffix), "")