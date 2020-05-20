#!/usr/bin/env python

__description__ = 'Excel json formula mid'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2020/05/20'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2020/05/20: sample 9e5f99a95a30b35d53799d88be16c68c

Todo:
"""

import sys
import json
import re

def StartsWithAndEndsWith(string, start, end):
    if not string.startswith(start):
        return None
    string = string[len(start):]
    if not string.endswith(end):
        return None
    return string[:-len(end)]
    
def UnQuote(string, quotecharacter='"'):
    if string[0] == quotecharacter and string[-1] == quotecharacter:
        return string[1:-1]
    else:
        return string

def Main():
    dCells = {}
    cells = json.loads(sys.stdin.read())
    for cell in cells:
        found = StartsWithAndEndsWith(cell[2], u'SET.VALUE(', u')')
        if found != None:
            cellref, value = found.split(',', 1)
            value = UnQuote(value)
            dCells[cellref] = value

    for cell in cells:
        regexFormula = r'^FORMULA\((.+),([a-zA-Z0-9]+)\)$'
        oMatch = re.match(regexFormula, cell[2])
        if oMatch != None:
            midstrings, cellref = oMatch.groups()
            formula = ''
            for mid in midstrings.split('&'):
                found = StartsWithAndEndsWith(mid, u'MID(', u')')
                if found != None:
                    cellref, offset, length = found.split(',')
                    formula += dCells[cellref][int(offset)-1]
            print(formula)

#        found = StartsWithAndEndsWith(cell[2], u'FORMULA(', u')')
#        if found != None:
#            print(found.split('&'))

if __name__ == '__main__':
    Main()
