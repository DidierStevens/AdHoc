#!/usr/bin/env python

from __future__ import print_function

__description__ = "Gootloader chroma parser"
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2022/12/04'

"""

Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2022/11/27: start from template for text file processing
  2022/12/04: refactoring

Todo:
"""

import optparse
import glob
import collections
import time
import sys
import textwrap
import os
import gzip
import re
import fnmatch
import collections
from contextlib import contextmanager
import ast
import json

def PrintManual():
    manual = '''
Manual:

This is a parser for Gootloader Chrome.js trojanized files, like:

1e5218156b91bf45ee3006d44defb840b314681115e1a6f63428e4037b7f7833
2e5771363f626d6f982f243c404a162ecc0aae1233ead19c30c9ae241aeb759a
4ae25ad28a889cae96e885d1dccf4ab5e552fb4a633b5aad967fcc8eb858a54f

It has a verbose mode.

It has JSON output mode.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

DEFAULT_SEPARATOR = ','
QUOTE = '"'

def PrintError(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

#Convert 2 Integer If Python 2
def C2IIP2(data):
    if sys.version_info[0] > 2:
        return data
    else:
        return ord(data)

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return list(map(lambda line:line.rstrip('\n'), f.readlines()))
    except:
        return None
    finally:
        f.close()

def Strings2File(filename, lines):
    try:
        f = open(filename, 'w')
    except:
        return None
    try:
        for line in lines:
            f.write(line + '\n')
        return True
    except:
        return None
    finally:
        f.close()

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]

# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression

# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)

class cVariables():
    def __init__(self, variablesstring='', separator=DEFAULT_SEPARATOR):
        self.dVariables = {}
        if variablesstring == '':
            return
        for variable in variablesstring.split(separator):
            name, value = VariableNameValue(variable)
            self.dVariables[name] = value

    def SetVariable(self, name, value):
        self.dVariables[name] = value

    def Instantiate(self, astring):
        for key, value in self.dVariables.items():
            astring = astring.replace('%' + key + '%', value)
        return astring

class cOutput():
    def __init__(self, filenameOption=None, encoding=''):
        self.starttime = time.time()
        self.filenameOption = filenameOption
        self.encoding = encoding
        self.encodingvalue, self.errorsvalue = ParseOptionEncoding('o', self.encoding)
        self.separateFiles = False
        self.progress = False
        self.console = False
        self.fOut = None
        self.rootFilenames = {}
        if self.filenameOption:
            if self.ParseHash(self.filenameOption):
                if not self.separateFiles and self.filename != '':
                    if sys.version_info[0] > 2:
                        self.fOut = open(self.filename, 'w', encoding=self.encodingvalue, errors=self.errorsvalue)
                    else:
                        self.fOut = open(self.filename, 'w')
            elif self.filenameOption != '':
                if sys.version_info[0] > 2:
                    self.fOut = open(self.filenameOption, 'w', encoding=self.encodingvalue, errors=self.errorsvalue)
                else:
                    self.fOut = open(self.filenameOption, 'w')

    def ParseHash(self, option):
        if option.startswith('#'):
            position = self.filenameOption.find('#', 1)
            if position > 1:
                switches = self.filenameOption[1:position]
                self.filename = self.filenameOption[position + 1:]
                for switch in switches:
                    if switch == 's':
                        self.separateFiles = True
                    elif switch == 'p':
                        self.progress = True
                    elif switch == 'c':
                        self.console = True
                    elif switch == 'l':
                        pass
                    elif switch == 'g':
                        if self.filename != '':
                            extra = self.filename + '-'
                        else:
                            extra = ''
                        self.filename = '%s-%s%s.txt' % (os.path.splitext(os.path.basename(sys.argv[0]))[0], extra, self.FormatTime())
                    else:
                        return False
                return True
        return False

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

    def RootUnique(self, root):
        if not root in self.rootFilenames:
            self.rootFilenames[root] = None
            return root
        iter = 1
        while True:
            newroot = '%s_%04d' % (root, iter)
            if not newroot in self.rootFilenames:
                self.rootFilenames[newroot] = None
                return newroot
            iter += 1

    def Line(self, line, eol='\n'):
        if self.fOut == None or self.console:
            try:
                print(line, end=eol)
            except UnicodeEncodeError:
                encoding = sys.stdout.encoding
                print(line.encode(encoding, errors='backslashreplace').decode(encoding), end=eol)
#            sys.stdout.flush()
        if self.fOut != None:
            self.fOut.write(line + '\n')
            self.fOut.flush()

    def LineTimestamped(self, line):
        self.Line('%s: %s' % (self.FormatTime(), line))

    def Filename(self, filename, index, total):
        self.separateFilename = filename
        if self.progress:
            if index == 0:
                eta = ''
            else:
                seconds = int(float((time.time() - self.starttime) / float(index)) * float(total - index))
                eta = 'estimation %d seconds left, finished %s ' % (seconds, self.FormatTime(time.time() + seconds))
            PrintError('%d/%d %s%s' % (index + 1, total, eta, self.separateFilename))
        if self.separateFiles and self.filename != '':
            oFilenameVariables = cVariables()
            oFilenameVariables.SetVariable('f', self.separateFilename)
            basename = os.path.basename(self.separateFilename)
            oFilenameVariables.SetVariable('b', basename)
            oFilenameVariables.SetVariable('d', os.path.dirname(self.separateFilename))
            root, extension = os.path.splitext(basename)
            oFilenameVariables.SetVariable('r', root)
            oFilenameVariables.SetVariable('ru', self.RootUnique(root))
            oFilenameVariables.SetVariable('e', extension)

            self.Close()
            if sys.version_info[0] > 2:
                self.fOut = open(oFilenameVariables.Instantiate(self.filename), 'w', encoding=self.encodingvalue, errors=self.errorsvalue)
            else:
                self.fOut = open(oFilenameVariables.Instantiate(self.filename), 'w')

    def Close(self):
        if self.fOut != None:
            self.fOut.close()
            self.fOut = None

class cExpandFilenameArguments():
    def __init__(self, filenames, literalfilenames=False, recursedir=False, checkfilenames=False, expressionprefix=None):
        self.containsUnixShellStyleWildcards = False
        self.warning = False
        self.message = ''
        self.filenameexpressions = []
        self.expressionprefix = expressionprefix
        self.literalfilenames = literalfilenames

        expression = ''
        if len(filenames) == 0:
            self.filenameexpressions = [['', '']]
        elif literalfilenames:
            self.filenameexpressions = [[filename, ''] for filename in filenames]
        elif recursedir:
            for dirwildcard in filenames:
                if expressionprefix != None and dirwildcard.startswith(expressionprefix):
                    expression = dirwildcard[len(expressionprefix):]
                else:
                    if dirwildcard.startswith('@'):
                        for filename in ProcessAt(dirwildcard):
                            self.filenameexpressions.append([filename, expression])
                    elif os.path.isfile(dirwildcard):
                        self.filenameexpressions.append([dirwildcard, expression])
                    else:
                        if os.path.isdir(dirwildcard):
                            dirname = dirwildcard
                            basename = '*'
                        else:
                            dirname, basename = os.path.split(dirwildcard)
                            if dirname == '':
                                dirname = '.'
                        for path, dirs, files in os.walk(dirname):
                            for filename in fnmatch.filter(files, basename):
                                self.filenameexpressions.append([os.path.join(path, filename), expression])
        else:
            for filename in list(collections.OrderedDict.fromkeys(sum(map(self.Glob, sum(map(ProcessAt, filenames), [])), []))):
                if expressionprefix != None and filename.startswith(expressionprefix):
                    expression = filename[len(expressionprefix):]
                else:
                    self.filenameexpressions.append([filename, expression])
            self.warning = self.containsUnixShellStyleWildcards and len(self.filenameexpressions) == 0
            if self.warning:
                self.message = "Your filename argument(s) contain Unix shell-style wildcards, but no files were matched.\nCheck your wildcard patterns or use option literalfilenames if you don't want wildcard pattern matching."
                return
        if self.filenameexpressions == [] and expression != '':
            self.filenameexpressions = [['', expression]]
        if checkfilenames:
            self.CheckIfFilesAreValid()

    def Glob(self, filename):
        if not ('?' in filename or '*' in filename or ('[' in filename and ']' in filename)):
            return [filename]
        self.containsUnixShellStyleWildcards = True
        return glob.glob(filename)

    def CheckIfFilesAreValid(self):
        valid = []
        doesnotexist = []
        isnotafile = []
        for filename, expression in self.filenameexpressions:
            hashfile = False
            try:
                hashfile = FilenameCheckHash(filename, self.literalfilenames)[0] == FCH_DATA
            except:
                pass
            if filename == '' or hashfile:
                valid.append([filename, expression])
            elif not os.path.exists(filename):
                doesnotexist.append(filename)
            elif not os.path.isfile(filename):
                isnotafile.append(filename)
            else:
                valid.append([filename, expression])
        self.filenameexpressions = valid
        if len(doesnotexist) > 0:
            self.warning = True
            self.message += 'The following files do not exist and will be skipped: ' + ' '.join(doesnotexist) + '\n'
        if len(isnotafile) > 0:
            self.warning = True
            self.message += 'The following files are not regular files and will be skipped: ' + ' '.join(isnotafile) + '\n'

    def Filenames(self):
        if self.expressionprefix == None:
            return [filename for filename, expression in self.filenameexpressions]
        else:
            return self.filenameexpressions

def ToString(value):
    if isinstance(value, str):
        return value
    else:
        return str(value)

def Quote(value, separator, quote):
    value = ToString(value)
    if separator in value or value == '':
        return quote + value + quote
    else:
        return value

def MakeCSVLine(row, separator, quote):
    return separator.join([Quote(value, separator, quote) for value in row])

class cLogfile():
    def __init__(self, keyword, comment):
        self.starttime = time.time()
        self.errors = 0
        if keyword == '':
            self.oOutput = None
        else:
            self.oOutput = cOutput('%s-%s-%s.log' % (os.path.splitext(os.path.basename(sys.argv[0]))[0], keyword, self.FormatTime()))
        self.Line('Start')
        self.Line('UTC', '%04d%02d%02d-%02d%02d%02d' % time.gmtime(time.time())[0:6])
        self.Line('Comment', comment)
        self.Line('Args', repr(sys.argv))
        self.Line('Version', __version__)
        self.Line('Python', repr(sys.version_info))
        self.Line('Platform', sys.platform)
        self.Line('CWD', repr(os.getcwd()))

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

    def Line(self, *line):
        if self.oOutput != None:
            self.oOutput.Line(MakeCSVLine((self.FormatTime(), ) + line, DEFAULT_SEPARATOR, QUOTE))

    def LineError(self, *line):
        self.Line('Error', *line)
        self.errors += 1

    def Close(self):
        if self.oOutput != None:
            self.Line('Finish', '%d error(s)' % self.errors, '%d second(s)' % (time.time() - self.starttime))
            self.oOutput.Close()

class cGrep():
    def __init__(self, expression, options):
        self.expression = expression
        self.options = options
        if self.expression == '' and self.options != '':
            raise Exception('Option --grepoptions can not be used without option --grep')
        self.dogrep = self.expression != ''
        self.oRE = None
        self.invert = False
        self.caseinsensitive = False
        self.fixedstring = False
        if self.dogrep:
            flags = 0
            for option in self.options:
                if option == 'i':
                    flags = re.IGNORECASE
                    self.caseinsensitive = True
                elif option == 'v':
                    self.invert = True
                elif option == 'F':
                    self.fixedstring = True
                else:
                    raise Exception('Unknown grep option: %s' % option)
            self.oRE = re.compile(self.expression, flags)

    def Grep(self, line):
        if self.fixedstring:
            if self.caseinsensitive:
                found = self.expression.lower() in line.lower()
            else:
                found = self.expression in line
            if self.invert:
                return not found, line
            else:
                return found, line
        else:
            oMatch = self.oRE.search(line)
            if self.invert:
                return oMatch == None, line
            if oMatch != None and len(oMatch.groups()) > 0:
                line = oMatch.groups()[0]
            return oMatch != None, line

def SearchAndReplace(line, search, replace, searchoptions):
    return line.replace(search, replace)

def FinalProcessing(line, options):
    if options.search != '':
        line = SearchAndReplace(line, options.search, options.replace, options.searchoptions)
    if options.trim != '':
        line = line[options.trim]
    return line

def ProcessFileWithoutContext(fIn, oBeginGrep, oGrep, oEndGrep, options, fullread):
    if fIn[0] == None:
        return

    begin = oBeginGrep == None or not oBeginGrep.dogrep
    end = False
    returnendline = False
    if fullread:
        yield fIn[0].read()
    else:
        for line in fIn[0]:
            if fIn[1] == 2:
                line = line.decode(*ParseOptionEncoding('i', options.encoding))
            line = line.rstrip('\n\r')
            if not begin:
                begin, line = oBeginGrep.Grep(line)
            if not begin:
                continue
            if not end and oEndGrep != None and oEndGrep.dogrep:
                end, line = oEndGrep.Grep(line)
                if end:
                    returnendline = True
            if end and not returnendline:
                continue
            selected = True
            if oGrep != None and oGrep.dogrep:
                selected, line = oGrep.Grep(line)
            if not selected:
                continue
            if end and returnendline:
                returnendline = False
            line = FinalProcessing(line, options)
            yield line

def ProcessFileWithContext(fIn, oBeginGrep, oGrep, oEndGrep, context, options, fullread):
    if fIn[0] == None:
        return

    begin = oBeginGrep == None or not oBeginGrep.dogrep
    end = False
    returnendline = False
    lineCounter = 0
    if len(context) >= 2:
        queueSize = context[1] - context[0] + 1
    elif context[0] < 0:
        queueSize = 0 - context[0] + 1
    else:
        queueSize = context[0] - 0 + 1
    queue = collections.deque([[-1, ''] for i in range(0, queueSize)])
    lineNumbers = []

    if fullread:
        yield fIn[0].read()
    else:
        for line in fIn[0]:
            lineCounter += 1
            if fIn[1] == 2:
                line = line.decode(*ParseOptionEncoding('i', options.encoding))
            line = line.rstrip('\n\r')
            if not begin:
                begin, line = oBeginGrep.Grep(line)
            if not begin:
                continue
            if not end and oEndGrep != None and oEndGrep.dogrep:
                end, line = oEndGrep.Grep(line)
                if end:
                    returnendline = True
            if end and not returnendline:
                continue
            queue.popleft()
            queue.append([lineCounter, line])
            selected, line = oGrep.Grep(line)
            if selected:
                lineNumbers = sorted(set(lineNumbers + [lineCounter + offset for offset in context]))
            if lineNumbers == []:
                continue
            else:
                for lineKey, lineValue in queue:
                    if lineNumbers[0] == lineKey:
                        line = lineValue
                        lineNumbers = lineNumbers[1:]
                        break
            if end and returnendline:
                returnendline = False
            line = FinalProcessing(line, options)
            yield line
        for line in lineNumbers:
            for lineKey, lineValue in queue:
                if line == lineKey:
                    yield lineValue
                    break

def ProcessFile(fIn, oBeginGrep, oGrep, oEndGrep, context, options, fullread):
    if oGrep != None and context != []:
        return ProcessFileWithContext(fIn, oBeginGrep, oGrep, oEndGrep, context, options, fullread)
    else:
        return ProcessFileWithoutContext(fIn, oBeginGrep, oGrep, oEndGrep, options, fullread)

def AnalyzeFileError(filename):
    PrintError('Error opening file %s' % filename)
    PrintError(sys.exc_info()[1])
    try:
        if not os.path.exists(filename):
            PrintError('The file does not exist')
        elif os.path.isdir(filename):
            PrintError('The file is a directory')
        elif not os.path.isfile(filename):
            PrintError('The file is not a regular file')
    except:
        pass

def ParseOptionEncodingSub2(encoding):
    if encoding == '':
        encodingvalue = 'utf8'
        errorsvalue = 'surrogateescape'
    elif ':' in encoding:
        encodingvalue, errorsvalue = encoding.split(':', 1)
    else:
        encodingvalue = encoding
        errorsvalue = None
    return encodingvalue, errorsvalue

def ParseOptionEncodingSub(entry):
    if not entry.startswith('i=') and not entry.startswith('o='):
        entry = 'i=' + entry
    stream, encoding = entry.split('=', 1)
    encodingvalue, errorsvalue = ParseOptionEncodingSub2(encoding)
    return stream, encodingvalue, errorsvalue

def ParseOptionEncoding(streamId, encoding):
    dStreamsPresent = {'i': False, 'o': False}
    dStreams = {'i': ['utf8', 'surrogateescape'], 'o': ['utf8', 'surrogateescape']}
    if encoding != '':
        for entry in encoding.split(','):
            stream, encodingvalue, errorsvalue = ParseOptionEncodingSub(entry)
            if dStreamsPresent[stream]:
                raise Exception('Encoding option error: %s' % encoding)
            else:
                dStreamsPresent[stream] = True
                dStreams[stream] = [encodingvalue, errorsvalue]
    return dStreams[streamId]

@contextmanager
def TextFile(filename, oLogfile, options):
    fType = 0
    if filename == '':
        fIn = sys.stdin
        fType = 1
    elif os.path.splitext(filename)[1].lower() == '.gz':
        try:
            fIn = gzip.GzipFile(filename, 'rb')
            fType = 2
        except:
            AnalyzeFileError(filename)
            oLogfile.LineError('Opening file %s %s' % (filename, repr(sys.exc_info()[1])))
            fIn = None
    else:
        try:
            if sys.version_info[0] > 2:
                fIn = open(filename, 'r', encoding=ParseOptionEncoding('i', options.encoding)[0], errors=ParseOptionEncoding('i', options.encoding)[1])
            else:
                fIn = open(filename, 'r')
        except:
            AnalyzeFileError(filename)
            oLogfile.LineError('Opening file %s %s' % (filename, repr(sys.exc_info()[1])))
            fIn = None

    if fIn != None:
        oLogfile.Line('Success', 'Opening file %s' % filename)

    yield (fIn, fType)

    if fIn != None:
        if sys.exc_info()[1] != None:
            oLogfile.LineError('Reading file %s %s' % (filename, repr(sys.exc_info()[1])))
        if fType != 1:
            fIn.close()

def ParseConcatenation(expression):
    oREDigits = re.compile("^[0-9]+$", re.I)
    oMatchDigits = oREDigits.match(expression)
    if oMatchDigits != None:
        return []
    return [variable.strip() for variable in expression.split('+')]

def BuildString(rootVar, dVarLeft, dVarString):
    if rootVar in dVarLeft:
        return ''.join([BuildString(variable, dVarLeft, dVarString) for variable in dVarLeft[rootVar]])
    else:
        return ast.literal_eval(dVarString[rootVar])

def Decoder(input):
    result = ''
    for index, character in enumerate(input):
        if index % 2 == 0:
            result = character + result
        else:
            result = result + character
    return result

def StartsWithGetRemainder(strIn, strStart):
    if strIn.startswith(strStart):
        return True, strIn[len(strStart):]
    else:
        return False, None

def ParseGootloaderFindRootVar(lines):
    function = None
    for index, line in enumerate(lines):
        if '""' in line:
            function = lines[index - 1]
            break
    if function == None:
        return [None, '"" not found']
    found, remainder = StartsWithGetRemainder(function, 'function ')
    if not found:
        return [None, "'function ' not found"]
    result = remainder.split('(')
    if len(result) == 0:
        return [None, "'(' not found"]
    functionName = result[0]

    rootVar = None
    for line in lines:
        line = line.strip()
        if functionName in line:
            oMatchFunction = re.match('^function ' + functionName + '\\(', line, re.I)
            oMatchCall = re.search(functionName + '\\(([a-z0-9]+)\\)', line, re.I)
            oMatchAssign = re.match('^.+ *= *' + functionName +';', line, re.I)
            if oMatchCall and not oMatchFunction:
                rootVar = oMatchCall.groups()[0]
            if oMatchAssign:
                pass

    return [functionName, rootVar]

def ParseGootloaderFindConcatExpression(lines):
    oREConcat = re.compile('{ *([a-z0-9]+) *= *([a-z0-9+]+);', re.I)
    concatExpression = ''
    for line in lines:
        line = line.strip()
        oMatchFunction = oREConcat.search(line)
        if oMatchFunction != None:
            if len(oMatchFunction.groups()[1]) > len(concatExpression):
                concatExpression = oMatchFunction.groups()[1]

    return concatExpression

def FindAll(data, sub):
    result = []
    start = 0
    while True:
        position = data.find(sub, start)
        if position == -1:
            return result
        result.append(position)
        start = position + 1

def ParseGootloaderSub1(lines, oOutput, options):
    dVarString = {}
    dVarLeft = {}
    dVarRight = {}

    oREVarString = re.compile("^([a-z0-9]+) *= *('.*'); *$", re.I)
    oREVarConcatenation = re.compile("^([a-z0-9]+) *= *([a-z0-9 +]+); *$", re.I)

    for line in lines:
        code = line.strip()
        oMatchVarString = oREVarString.match(code)
        oMatchVarConcatenation = oREVarConcatenation.match(code)
        if oMatchVarString != None:
            dVarString[oMatchVarString.groups()[0]] = oMatchVarString.groups()[1]
        elif oMatchVarConcatenation != None:
            variables = ParseConcatenation(oMatchVarConcatenation.groups()[1])
            if variables != []:
                dVarLeft[oMatchVarConcatenation.groups()[0]] = variables
                for variable in variables:
                    dVarRight[variable] = True

    for variable in dVarLeft:
        if not variable in dVarRight:
            if options.verbose:
                oOutput.Line(variable)

    return dVarString, dVarLeft, dVarRight

def ParseGootloaderSub2(deobfuscated1, oOutput, options):
    oREStrSingleQuote = re.compile("^[^']+('.+')[^']+$")
    oMatchStr = oREStrSingleQuote.match(deobfuscated1)
    level2 = ast.literal_eval(oMatchStr.groups()[0])
    if options.verbose:
        oOutput.Line('-' * 40)
        oOutput.Line(level2)
    deobfuscated2 = Decoder(level2)
    if options.verbose:
        oOutput.Line('-' * 40)
        oOutput.Line(deobfuscated2)
    return deobfuscated2

def ParseGootloader2(lines, oOutput, options):
    concatExpression = ParseGootloaderFindConcatExpression(lines)

    dVarString, dVarLeft, dVarRight = ParseGootloaderSub1(lines, oOutput, options)

    level1 = ''
    for variable in concatExpression.split('+'):
        level1 += BuildString(variable, dVarLeft, dVarString)
    if options.verbose:
        oOutput.Line('-' * 40)
        oOutput.Line(level1)
    deobfuscated1 = Decoder(level1)
    if options.verbose:
        oOutput.Line('-' * 40)
        oOutput.Line(deobfuscated1)

    deobfuscated2 = ParseGootloaderSub2(deobfuscated1, oOutput, options)

    if options.verbose:
        oOutput.Line('-' * 40)
    if len(FindAll(deobfuscated2, "'+'")) > len(FindAll(deobfuscated2, "')+('")):
        deobfuscated3 = deobfuscated2.replace("'+'", '')
    elif "')+('" in deobfuscated2:
        deobfuscated3 = deobfuscated2.replace("')+('", '')
    if options.verbose:
        oOutput.Line(deobfuscated3)

    allDoubleQuotedString = [str for str in re.findall('".*?"', deobfuscated3, re.I) if len(str) > 8 and not str.startswith('''"'+''')]
    if options.verbose:
        oOutput.Line('-' * 40)
        for doubleQuotedString in allDoubleQuotedString:
            oOutput.Line(doubleQuotedString)
    if options.json:
        glid = allDoubleQuotedString[0].strip('"')
        uas = allDoubleQuotedString[1].strip('"')
        urls = [url.strip('"') for url in allDoubleQuotedString[3:]]
        with open('urls-%s.json' % glid, 'w') as fOut:
            dJSON = {'glid': glid, 'uas': uas, 'urls': urls}
            fOut.write(json.dumps(dJSON))
            oOutput.Line('Wrote: %s' % json.dumps(dJSON))
    else:
        oOutput.Line('-' * 40)
        oOutput.Line('ID: %s' % allDoubleQuotedString[0])
        oOutput.Line('UAS: %s' % allDoubleQuotedString[1])
        if not allDoubleQuotedString[2].startswith('"Cookie: '):
            oOutput.Line('Cookie: %s' % allDoubleQuotedString[2])
        for doubleQuotedString in allDoubleQuotedString[3:]:
            oOutput.Line('URL: %s' % doubleQuotedString)

def ParseGootloader1(lines, oOutput, options):
    functionName, rootVar = ParseGootloaderFindRootVar(lines)
    if functionName == None:
        if options.verbose:
            oOutput.Line('ParseGootloaderFindRootVar failed: %s' % rootVar)
        return
    if options.verbose:
        oOutput.Line('functionName: %s' % functionName)
        oOutput.Line('rootVar: %s' % rootVar)

    dVarString, dVarLeft, dVarRight = ParseGootloaderSub1(lines, oOutput, options)

    level1 = BuildString(rootVar, dVarLeft, dVarString)
    if options.verbose:
        oOutput.Line('-' * 40)
        oOutput.Line(level1)
    deobfuscated1 = Decoder(level1)
    if options.verbose:
        oOutput.Line('-' * 40)
        oOutput.Line(deobfuscated1)

    deobfuscated2 = ParseGootloaderSub2(deobfuscated1, oOutput, options)

    allDoubleQuotedString = [str for str in re.findall('".*?"', deobfuscated2, re.I) if not str in ['"|"', '"\\\\"', '""', '";"', '"ID"']]
    if options.verbose:
        oOutput.Line('-' * 40)
        oOutput.Line(allDoubleQuotedString)

    words = ast.literal_eval(allDoubleQuotedString[0])
    if options.verbose:
        oOutput.Line(words)

    if options.verbose:
        oOutput.Line('-' * 40)
    expectedWords = ['UserId', 'abcdefghijklmnopqrstuvwxyz', 'ExpandEnvironmentStrings', 'Create', 'random', 'Path', 'OpenTextFile', 'Quit', 'split', 'NewTask', 'CreateObject', 'StartWhenAvailable', 'name', 'wscript', 'moveNext', 'RunEx', '%APPDATA%', 'atEnd', 'SubFolders', 'GetFile', 'round', 'RegisterTaskDefinition', 'Hidden', 'Schedule.Service', 'GetFolder', 'floor', '%USERDOMAIN%\%USERNAME%', 'WorkingDirectory', 'Actions', 'Connect', 'Arguments', 'LogonTriggerId', 'ShortName', 'settings', 'Count', 'Close', 'triggers', 'WScript.Shell', 'item', 'GetTask', 'Write', 'FileExists', 'Scripting.FileSystemObject']
    unexpectedWords = []
    words = words.split('|')
    for i in range(len(words)):
        word = words[i]
        for j in range(i + 1):
            word = word[1:] + word[0:1]
        if options.verbose:
            oOutput.Line('%d: %s' % (i, word))
        if not word in expectedWords:
            unexpectedWords.append(word)

    oREConcatenation = re.compile('\(([a-z0-9]+\+[a-z0-9+]+)\)', re.I)
    oMatchConcatenation = oREConcatenation.search(deobfuscated2)
    if options.verbose:
        oOutput.Line('-' * 40)
    concatenation = oMatchConcatenation.groups()[0]
    if options.verbose:
        oOutput.Line(concatenation)

    level3 = ''
    for variable in concatenation.split('+'):
        level3 += BuildString(variable, dVarLeft, dVarString)
    if options.verbose:
        oOutput.Line('-' * 40)
        oOutput.Line(level3)

    deobfuscated3 = Decoder(level3)
    if options.verbose:
        oOutput.Line('-' * 40)
        oOutput.Line(deobfuscated3)

        oOutput.Line('-' * 40)

    lines3 = []
    line3 = ''
    insideString = False
    for index, character in enumerate(' ' + deobfuscated3):
        if character == "'" and deobfuscated3[index-2] != '\\':
            insideString = not insideString
            line3 += character
        elif character in [';', '}']:
            line3 += character
            if not insideString:
                lines3.append(line3)
                line3 = ''
        else:
            line3 += character
    lines3.append(line3)

    if options.verbose:
        oOutput.Line('\n'.join(lines3))
        oOutput.Line('-' * 40)
    ParseGootloader2(lines3, oOutput, options)

    if not options.json:
        oOutput.Line('-' * 40)
    if options.verbose:
        oOutput.Line(unexpectedWords)
        oOutput.Line(allDoubleQuotedString[1:])
    logFilename = None
    jsFilename = None
    taskName = None
    wordsToCheck = unexpectedWords + allDoubleQuotedString[1:]
    wordsToCheck = [word.strip('"') for word in wordsToCheck]
    if len(wordsToCheck) != 3:
        oOutput.Line(wordsToCheck)
    for word in wordsToCheck:
        if word.lower().endswith('.log'):
            logFilename = word
        elif word.lower().endswith('.js'):
            jsFilename = word
        else:
            taskName = word
    if not options.json:
        oOutput.Line('logFilename: %s' % logFilename)
        oOutput.Line('jsFilename: %s' % jsFilename)
        oOutput.Line('taskName: %s' % taskName)
        oOutput.Line('-' * 40)

def ProcessTextFile(filename, oBeginGrep, oGrep, oEndGrep, context, oOutput, oLogfile, options):
    with TextFile(filename, oLogfile, options) as fIn:
        try:
            lines = []
            if not options.json:
                oOutput.Line('Filename: %s' % filename)
            for line in ProcessFile(fIn, oBeginGrep, oGrep, oEndGrep, context, options, False):
                # ----- Put your line processing code here -----
                lines.append(line)
                # ----------------------------------------------
            ParseGootloader1(lines, oOutput, options)
        except:
            oLogfile.LineError('Processing file %s %s' % (filename, repr(sys.exc_info()[1])))
            if not options.ignoreprocessingerrors:
                raise
            if sys.version_info[0] < 3:
                sys.exc_clear()

def InstantiateCOutput(options):
    filenameOption = None
    if options.output != '':
        filenameOption = options.output
    return cOutput(filenameOption, options.encoding)

def ParseNumber(number):
    negative = 1
    if number[0] == '-':
        negative = -1
        number = number[1:]
    elif number[0] == '+':
        number = number[1:]
    digits = ''
    while len(number) > 0 and number[0] >= '0' and number[0] <= '9':
        digits += number[0]
        number = number[1:]
    return negative * int(digits), number

def ParseTerm(term):
    start, remainder = ParseNumber(term)
    if len(remainder) == 0:
        return [start]
    if remainder[0] == '-':
        remainder = remainder[1:]
        stop, remainder = ParseNumber(remainder)
        if len(remainder) > 0:
            raise Exception('Error parsing term: ' + term)
        return list(range(start, stop + 1))
    else:
        raise Exception('Error parsing term: ' + term)

def ParseContext(context):
    lines = []
    for term in context.replace(' ', '').split(','):
        lines += ParseTerm(term)
    return sorted(set(lines))

def ProcessTextFiles(filenames, oLogfile, options):
    oGrep = cGrep(options.grep, options.grepoptions)
    oBeginGrep = cGrep(options.begingrep, options.begingrepoptions)
    oEndGrep = cGrep(options.endgrep, options.endgrepoptions)
    oOutput = InstantiateCOutput(options)
    if oGrep == None or not oGrep.dogrep:
        context = []
    elif options.context == '':
        context = []
    else:
        context = ParseContext(options.context)

    if options.trim != '':
        begin, end = options.trim.split(':', 2)
        if begin == '':
            begin = None
        else:
            begin = int(begin)
        if end == '':
            end = None
        else:
            end = int(end)
        options.trim = slice(begin, end)

    for index, filename in enumerate(filenames):
        oOutput.Filename(filename, index, len(filenames))
        ProcessTextFile(filename, oBeginGrep, oGrep, oEndGrep, context, oOutput, oLogfile, options)

    oOutput.Close()

def Main():
    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [[@]file ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file (# supported)')
    oParser.add_option('-j', '--json', action='store_true', default=False, help='Produce JSON output')
    oParser.add_option('-V', '--verbose', action='store_true', default=False, help='Be verbose')
    oParser.add_option('--grep', type=str, default='', help='Grep expression')
    oParser.add_option('--grepoptions', type=str, default='', help='grep options (ivF)')
    oParser.add_option('--context', type=str, default='', help='Grep context (lines to select)')
    oParser.add_option('--begingrep', type=str, default='', help='Grep expression for begin line')
    oParser.add_option('--begingrepoptions', type=str, default='', help='begingrep options (ivF)')
    oParser.add_option('--endgrep', type=str, default='', help='Grep expression for end line')
    oParser.add_option('--endgrepoptions', type=str, default='', help='endgrep options (ivF)')
    oParser.add_option('--search', type=str, default='', help='Search term (search and replace)')
    oParser.add_option('--replace', type=str, default='', help='Replace term (search and replace)')
    oParser.add_option('--searchoptions', type=str, default='', help='Search options (search and replace)')
    oParser.add_option('--trim', type=str, default='', help='Trim line with a Python slice (begin:end)')
    oParser.add_option('--withfilename', type=str, default='', help='Include filename with output with given separator')
    oParser.add_option('--literalfilenames', action='store_true', default=False, help='Do not interpret filenames')
    oParser.add_option('--recursedir', action='store_true', default=False, help='Recurse directories (wildcards and here files (@...) allowed)')
    oParser.add_option('--checkfilenames', action='store_true', default=False, help='Perform check if files exist prior to file processing')
    oParser.add_option('--logfile', type=str, default='', help='Create logfile with given keyword')
    oParser.add_option('--logcomment', type=str, default='', help='A string with comments to be included in the log file')
    oParser.add_option('--ignoreprocessingerrors', action='store_true', default=False, help='Ignore errors during file processing')
    oParser.add_option('--encoding', type=str, default='', help='Encoding for file open')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    oLogfile = cLogfile(options.logfile, options.logcomment)

    oExpandFilenameArguments = cExpandFilenameArguments(args, options.literalfilenames, options.recursedir, options.checkfilenames)
    oLogfile.Line('FilesCount', str(len(oExpandFilenameArguments.Filenames())))
    oLogfile.Line('Files', repr(oExpandFilenameArguments.Filenames()))
    if oExpandFilenameArguments.warning:
        PrintError('\nWarning:')
        PrintError(oExpandFilenameArguments.message)
        oLogfile.Line('Warning', repr(oExpandFilenameArguments.message))

    ProcessTextFiles(oExpandFilenameArguments.Filenames(), oLogfile, options)

    if oLogfile.errors > 0:
        PrintError('Number of errors: %d' % oLogfile.errors)
    oLogfile.Close()

if __name__ == '__main__':
    Main()
