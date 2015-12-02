"""
    @Autor
    Julian J. Gonzalez

    @Lib
    ST2Labs / GEO SYSTEM SOFTWARE
    DFTime v1.0

    @Description

        Digital Forensics Time is a free tool for
        easy way to convert Timestamp in Hex to Date
        Often appears in SQLite db files: example
        msgstore.db (WhatsApp)

    @Usage

        Input: milliseconds timestamp in hex data
        Output: Date format

    @License
    This is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation version 2 of the License.
    Thi is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along it; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    @Contact
    julian.gonzalez[at]seguridadparatodos[dot]es
    www.seguridadparatodos.es | www.st2labs.es

    #ST2Labs | #DFIR | #Forensics
"""
import sys
import hashlib

credit = str('''
     ___  ___ _____ _
    |   \| __|_   _(_)_ __  ___
    | |) | _|  | | | | '  \/ -_)
    |___/|_|   |_| |_|_|_|_\___|

    Digital Forensics Time v 1.0
    ---

    DFTime is a free converter
    tool for WhatsApp SQLite
    timestamp and others.

            GEO SYSTEM SOFTWARE
                        ST2Labs

    ''')

error_1 = str('\n' +
              '  Wrong input length data' +
              '\n' +
              '  Please, use hexa data with 6 bytes size' +
              '\n' +
              '  Example: 01513407f338' +
              '\n')

error_2 = str('' +
              'Somenthing was wrong' +
              'Please check input value' +
              '')


def _get_sha1hex_(patern_):
    return hashlib.sha1(patern_).hexdigest()


def _HextoInt(v_):
    # Return value Hex from bytes
    return int(v_, 16)


def _decode_timestamp(ms):
    import datetime
    ms = float(str(ms)[0:-3])
    utc_time = datetime.datetime.utcfromtimestamp(ms)
    return utc_time


if __name__ == "__main__":

    try:
        # Expected  hex data
        # Example: 6 bytes like this: '01513407f338'
        t = sys.argv[1:][0]

        if (len(t) / 2) != 6:
            print error_1
            sys.exit(2)
        dt = _decode_timestamp(_HextoInt(t))

        print ''
        print credit
        print '    Input'
        print '    Timestamp {}'.format(t)
        print '    ---'
        print ''
        print '    Results:'
        print '    {}'.format(dt)
        print '    ---'
        print ''
        print '    SHA1 Hash for Results'
        print '    ---'
        print '    {}'.format(_get_sha1hex_(str(dt)))
        print ''

    except Exception, e:
        print error_2
        print '  Error: %s' % e
        sys.exit(2)
