#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Excel brute force formula fill'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2020/05/22'

"""

Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2020/05/12: start sample ba5f47015284fe7c03e89923fcc6cc92
  2020/05/16: continue
  2020/05/17: continue
  2020/05/18: continue
  2020/05/20: continue sample 565462bf06374d8daf51f99510339945
  2020/05/22: MyEval

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
import csv
import math
import string
from contextlib import contextmanager

def PrintManual():
    manual = '''
Manual:

TBC

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

DEFAULT_SEPARATOR = ','
QUOTE = '"'
CELLREFERENCE_LN = r'([A-Z]+[0-9]+)'
CELLREFERENCE_RC = r'(R[0-9]+C[0-9]+)'
CELLREFERENCE = None

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

def P23Ord(value):
    if type(value) == int:
        return value
    else:
        return ord(value)

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
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
    def __init__(self, filenameOption=None):
        self.starttime = time.time()
        self.filenameOption = filenameOption
        self.separateFiles = False
        self.progress = False
        self.console = False
        self.fOut = None
        self.rootFilenames = {}
        if self.filenameOption:
            if self.ParseHash(self.filenameOption):
                if not self.separateFiles and self.filename != '':
                    self.fOut = open(self.filename, 'w')
            elif self.filenameOption != '':
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

def ProcessFileWithoutContext(fIn, oBeginGrep, oGrep, oEndGrep, options, fullread):
    if fIn == None:
        return

    begin = oBeginGrep == None or not oBeginGrep.dogrep
    end = False
    returnendline = False
    if fullread:
        yield fIn.read()
    else:
        for line in fIn:
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
            if options.search != '':
                line = SearchAndReplace(line, options.search, options.replace, options.searchoptions)
            yield line

def ProcessFileWithContext(fIn, oBeginGrep, oGrep, oEndGrep, context, options, fullread):
    if fIn == None:
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
        yield fIn.read()
    else:
        for line in fIn:
            lineCounter += 1
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
            if options.search != '':
                line = SearchAndReplace(line, options.search, options.replace, options.searchoptions)
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

@contextmanager
def TextFile(filename, oLogfile):
    if filename == '':
        fIn = sys.stdin
    elif os.path.splitext(filename)[1].lower() == '.gz':
        try:
            fIn = gzip.GzipFile(filename, 'rb')
        except:
            AnalyzeFileError(filename)
            oLogfile.LineError('Opening file %s %s' % (filename, repr(sys.exc_info()[1])))
            fIn = None
    else:
        try:
            fIn = open(filename, 'r')
        except:
            AnalyzeFileError(filename)
            oLogfile.LineError('Opening file %s %s' % (filename, repr(sys.exc_info()[1])))
            fIn = None

    if fIn != None:
        oLogfile.Line('Success', 'Opening file %s' % filename)

    yield fIn

    if fIn != None:
        if sys.exc_info()[1] != None:
            oLogfile.LineError('Reading file %s %s' % (filename, repr(sys.exc_info()[1])))
        if fIn != sys.stdin:
            fIn.close()

def EvalGetCellCallback(oMatch):
    global dCells

    result = 'error'
    type_num, reference = oMatch.groups()

    if type_num == '50':
        if dCells[reference][3] == '8':
            result = '2'
        elif dCells[reference][3] == '2':
            result = '1'
        else:
            print(dCells[reference])
    elif type_num == '38':
        if dCells[reference][3] == '9':
            result = '15'
        elif dCells[reference][3] == '11':
            result = '7'
        elif dCells[reference][3] == '1':
            result = '5'
        elif dCells[reference][3] == '3':
            result = '12'
        elif dCells[reference][3] == '10':
            result = '3'
        else:
            print(dCells[reference])
    elif type_num == '19':
        if dCells[reference][3] == '7':
            result = '20'
        elif dCells[reference][3] == '5':
            result = '5'
        elif dCells[reference][3] == '12':
            result = '3'
        else:
            print(dCells[reference])
    elif type_num == '17':
        if reference in dCells:
           print(dCells[reference])
        else:
            return '15'
    elif type_num == '24':
        if dCells[reference][3] == '6':
            result = '12'
        elif dCells[reference][3] == '4':
            result = '11'
        else:
            print(dCells[reference])
    else:
        if reference in dCells:
           print(dCells[reference])

    return result

def EvalGetCell(formula):
    return re.sub(r'GET.CELL\s*\(\s*([0-9]+)\s*,\s*' + CELLREFERENCE + r'\s*\)', EvalGetCellCallback, formula)

def IntToFloatStringCallback(oMatch):
    if '.' in oMatch.group():
        return oMatch.group()
    else:
        return oMatch.group() + '.0'

def IntToFloatString(formula):
    return re.sub(r'[0-9.]+', IntToFloatStringCallback, formula)

def CalculatePrevalence(data):
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[P23Ord(char)] += 1
    return dPrevalence

def CalculateByteStatistics(dPrevalence):
    sumValues = sum(dPrevalence.values())
    countNullByte = dPrevalence[0]
    countControlBytes = 0
    countWhitespaceBytes = 0
    for iter in range(1, 0x21):
        if chr(iter) in string.whitespace:
            countWhitespaceBytes += dPrevalence[iter]
        else:
            countControlBytes += dPrevalence[iter]
    countControlBytes += dPrevalence[0x7F]
    countPrintableBytes = 0
    for iter in range(0x21, 0x7F):
        countPrintableBytes += dPrevalence[iter]
    countHighBytes = 0
    for iter in range(0x80, 0x100):
        countHighBytes += dPrevalence[iter]
    entropy = 0.0
    for iter in range(0x100):
        if dPrevalence[iter] > 0:
            prevalence = float(dPrevalence[iter]) / float(sumValues)
            entropy += - prevalence * math.log(prevalence, 2)
    countLetters = 0
    for iter in range(0x41, 0x5B):
        countLetters += dPrevalence[iter]
    for iter in range(0x61, 0x7B):
        countLetters += dPrevalence[iter]
    return sumValues, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes, countLetters

def MyEval(expression):
    sumValues, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes, countLetters = CalculateByteStatistics(CalculatePrevalence(expression))
    if countLetters > 0:
        raise('MyEval: expression with letters: ' + expression)
    else:
        return eval(expression)

def BruteForceGetCell(formula):
    oMatch = re.search(r'^(.*)(GET.CELL\s*\(\s*)([0-9]+)(\s*,\s*)' + CELLREFERENCE + r'(\s*\))(.*)$', formula)
    if oMatch == None:
        return []
    result = []
    dBruteForceRanges = {
        '8': [1, 7], # Number indicating the cell's horizontal alignment
        '17': [0, 255], # Row height of cell, in points.
        '19': [0, 255], # Size of font, in points.
        '24': [0, 56], # Font color of the first character in the cell, as a number in the range 1 to 56. If font color is automatic, returns 0.
        '38': [0, 56], # Shade foreground color as a number in the range 1 to 56. If color is automatic, returns 0.
        '50': [1, 4], # Number indicating the cell's vertical alignment
    }
    defaultBruteForceRange = [0, 255]
    if not oMatch.groups()[2] in dBruteForceRanges:
        print(formula)
        print(oMatch.groups()[2])
    begin, end = dBruteForceRanges.get(oMatch.groups()[2], defaultBruteForceRange)
    for i in range(begin, end + 1):
        try:
            formula = oMatch.groups()[0] + str(i) + oMatch.groups()[6]
            value = MyEval(IntToFloatString(formula))
            result.append(str(value))
        except:
            pass
    return result

def MyChr(value):
    value = int(value)
    if value < 0 or value > 255:
        value = 0x20
    return chr(value)

def SolveFormula(values, position, expected, dCells):
    leftCell = values[0][position][0]
    operator = values[0][position][1]
    rightCell = values[0][position][2]
    if type(dCells.get(leftCell, None)[2]) == type([]):
        values = []
        for bruteforcevalue in dCells.get(leftCell)[2]:
            result = None
            if operator in ['+', '-', '*', '/']:
                result = MyChr(MyEval(bruteforcevalue + operator + dCells[rightCell][2]))
            else:
                raise Exception('Unknown operator: ' + operator)
            if result == expected:
                values.append(bruteforcevalue)
        if values != []:
            stored = dCells[leftCell]
            if len(values) == 1:
                stored = stored[0:2] + values
            else:
                stored = stored[0:2] + [values]
            dCells[leftCell] = stored

def PartialMatch(value, expected):
    matches = 0
    if len(value) != len(expected):
        return 0
    for i in range(len(value)):
        if value[i] == expected[i]:
            if expected[i] != ' ':
                matches += 1
            continue
        if value[i] != ' ':
            return 0
    return matches

def SolveForExpected(dFormulas, expected, dCells):
    for key, values in dFormulas.items():
        if PartialMatch(values[1], expected) != 0:
            for i, c in enumerate(values[1]):
                if c == ' ' and expected[i] != ' ':
                    SolveFormula(values, i, expected[i], dCells)

def StartsWithAndEndsWith(string, start, end):
    if not string.startswith(start):
        return None
    string = string[len(start):]
    if not string.endswith(end):
        return None
    return string[:-len(end)]

def TryFormulas(dFormulas, dCells):
    for key, values in dFormulas.items():
        result = ''
        for leftCell, operator, rightCell in values[0]:
            if leftCell in dCells and rightCell in dCells:
                if type(dCells[leftCell][2]) == type([]):
                    result += ' '
                elif operator in ['+', '-', '*', '/']:
                    result += MyChr(MyEval(dCells[leftCell][2] + operator + dCells[rightCell][2]))
                else:
                    raise Exception('TryFormulas 1')
            else:
                result += ' '
        dFormulas[key] = [values[0], result]

def ProcessTextFile(filename, oBeginGrep, oGrep, oEndGrep, context, oOutput, oLogfile, options):
    global dCells
    global CELLREFERENCE

    with TextFile(filename, oLogfile) as fIn:
        try:
            dCells = {}
            reader = csv.reader(fIn, delimiter=',', skipinitialspace=False, quoting=csv.QUOTE_MINIMAL)
            skipHeader = True
            index = 0
            CELLREFERENCE = None
            for row in reader:
                if skipHeader:
                    skipHeader = False
                    if row[0] == 'Sheet':
                        index = 1
                    continue
                rowCut = row[index:]
                dCells[rowCut[0]] = rowCut
                if len(rowCut) != 3:
                    raise Exception('Error row length: ' + repr(row))
                if CELLREFERENCE == None:
                    if re.match(CELLREFERENCE_RC, rowCut[0]):
                        CELLREFERENCE = CELLREFERENCE_RC
                    elif re.match(CELLREFERENCE_LN, rowCut[0]):
                        CELLREFERENCE = CELLREFERENCE_LN
                    else:
                        raise Exception('Error reference: ' + row[0])

            for key, row in dCells.items():
                match = StartsWithAndEndsWith(row[1], 'SET.VALUE(', ')')
                if match != None:
                    cell, formula = match.split(',', 1)
                    bruteforce = BruteForceGetCell(formula)
                    if bruteforce == []:
                        try:
                            expression = IntToFloatString(formula)
                            value = MyEval(expression)
                            dCells[cell] = [cell, '', str(value)]
                        except:
                            print(row)
                    else:
                        dCells[cell] = [cell, '', bruteforce]

            oRE = re.compile(r'^CHAR\(' + CELLREFERENCE + r'(.)' + CELLREFERENCE + r'\)$')

            dFormulas = {}
            for key, row in dCells.items():
                matchFormula = StartsWithAndEndsWith(row[1], 'FORMULA(', ')')
                if matchFormula == None:
                    matchFormula = StartsWithAndEndsWith(row[1], 'FORMULA.FILL(', ')')
                if matchFormula != None:
                    chars = []
                    for char in matchFormula.split(',')[0].split('&'):
                        oMatch = oRE.search(char)
                        if oMatch != None:
                            chars.append(oMatch.groups())
                        else:
                            raise Exception('1')
                    dFormulas[row[1]] = [chars, None]

#            dFormulas = {key: value for key, value in dFormulas.items() if len(value[0]) == 15}
#            print(dFormulas)

            for key, values in dFormulas.items():
                SolveFormula(values, 0, '=', dCells)
            TryFormulas(dFormulas, dCells)

            wellknowns = [
                '=APP.MAXIMIZE()',
                '=CLOSE(FALSE)',
                '=NEXT()',
                '''="The workbook cannot be opened or repaired by Microsoft Excel because it's corrupt."''',
                '="https://docs.microsoft.com/en-us/officeupdates/office-msi-non-security-updates"',
                '="C:\\Windows\\system32\\reg.exe"',
                '=WAIT(NOW()+"00:00:01")',
                '="C:\\Windows\\system32\\rundll32.exe"',
                '="EXPORT HKCU\\Software\\Microsoft\\Office\\"',
            ]
            for wellknown in wellknowns:
                SolveForExpected(dFormulas, wellknown, dCells)
            TryFormulas(dFormulas, dCells)

            if options.expected != '':
                for expected in File2Strings(options.expected):
                    SolveForExpected(dFormulas, expected, dCells)
                TryFormulas(dFormulas, dCells)

            for key, row in dFormulas.items():
                oOutput.Line(row[1])

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
    return cOutput(filenameOption)

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
    oParser.add_option('-e', '--expected', type=str, default='', help='File with expected strings')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file (# supported)')
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
    oParser.add_option('--literalfilenames', action='store_true', default=False, help='Do not interpret filenames')
    oParser.add_option('--recursedir', action='store_true', default=False, help='Recurse directories (wildcards and here files (@...) allowed)')
    oParser.add_option('--checkfilenames', action='store_true', default=False, help='Perform check if files exist prior to file processing')
    oParser.add_option('--logfile', type=str, default='', help='Create logfile with given keyword')
    oParser.add_option('--logcomment', type=str, default='', help='A string with comments to be included in the log file')
    oParser.add_option('--ignoreprocessingerrors', action='store_true', default=False, help='Ignore errors during file processing')
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
