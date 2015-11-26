"""
    @Autor
    Julian J. Gonzalez

    @Lib
    ST2Labs / GEO SYSTEM SOFTWARE
    sqlite_ex v1.0

    @Description

        In Digital Forensics, sqlite_ex is a free tool for
        easy way to extract db_schema to file or stdout
        and show information field for any SQLite table_info
        in database

    @Usage

        python sqlite_ex.py     <data_base.db>
        python sqlite_ex.py  -d <data_base.db>
        python sqlite_ex.py  -o <filename> <data_base.db>
        python sqlite_ex.py  -i <tablename> <data_base.db>

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
import os
import sqlite3
import argparse


def usage():
    print '''

     ___  ___  _    _ _         _____  __
    / __|/ _ \| |  (_) |_ ___  | __\ \/ /
    \__ \ (_) | |__| |  _/ -_) | _| >  <
    |___/\__\_\____|_|\__\___| |___/_/\_\\

     SQLite Extract Database schema tool
     ---

     Usage()

        python sqlite_ex.py     <data_base.db>
        python sqlite_ex.py  -d <data_base.db>
        python sqlite_ex.py  -o <filename> <data_base.db>
        python sqlite_ex.py  -i <tablename> <data_base.db>

    '''


def to_sql(f_name):
    # Convert file existing_db.db to SQL dump file dump.sql
    con = sqlite3.connect(f_name)
    name = str(f_name + 'dump.sql')
    with open(name, 'w') as f:
        for line in con.iterdump():
            f.write('%s\n' % line)
        to_sha1(f.name)

    print '    Dump SQLite Database complete'


def to_stdout(cursor):
    sql_type = ['Type', 'Name', 'T_Name', 'Root_Page', 'Query']
    for item in cursor.fetchall():
        print '   {:>12}'.format('---')
        for nl in xrange(len(item)):
            print '    {:>12} - {:<5}'.format(sql_type[nl], item[nl])
        print ''


def to_file(f_name, f_out):

    sql_type = ['Type', 'Name', 'T_Name', 'Root_Page', 'Query']
    con = sqlite3.connect(f_name)
    cursor = con.cursor()
    cursor.execute("SELECT * FROM sqlite_master;")

    f_out = str(f_out + '.schema')
    with open(f_out, 'w') as f:
        for item in cursor.fetchall():
            f.write('   {:>12}'.format('---'))
            f.write('\n')
            for nl in xrange(len(item)):
                f.write('    {:>12} - {:<5}'.format(sql_type[nl], item[nl]))
                f.write('\n')
            f.write('\n')
        to_sha1(f.name)
        print '    SQLite Database Schema save in {}'.format(f.name)


def get_sha1hex_(patern_):
    import hashlib
    return hashlib.sha1(patern_).hexdigest()


def to_sha1(filepath):
    import hashlib
    with open(filepath, 'rb') as f:
        text_ = hashlib.sha1(f.read()).hexdigest()

    filepath = str(filepath + '.sha1')
    with open(filepath, 'w') as f:
        f.write(text_)
        f.close()


def is_valid(f_name):
    SL_header_hex = '53514c69746520666f726d6174203300'
    v = True
    try:
        with open(f_name, 'rb') as f:
            header_hex = f.read(16).encode('hex')
            if header_hex != SL_header_hex:
                v = False
            return v
    except Exception, e:
        print "Somenthing was wrong! %s" % e


def get_sql_master(f_name):

    con = sqlite3.connect(f_name)
    cursor = con.cursor()
    cursor.execute("SELECT * FROM sqlite_master;")

    return cursor


def get_metadata(f_name, t_name):

    con = sqlite3.connect(f_name)
    cursor = con.cursor()

    query = str('PRAGMA table_info(' +
                t_name +
                ')')
    meta = cursor.execute(query)

    print '    Info for Table: {}'.format(t_name)
    print '    {}'.format('---')
    pos = 0
    for i in meta:
        print '    Col {:>2}: {}'.format(pos, i[1])
        pos = pos + 1
    return meta


def main(argv):

    print '''
      ___  ___  _    _ _         _____  __
     / __|/ _ \| |  (_) |_ ___  | __\ \/ /
     \__ \ (_) | |__| |  _/ -_) | _| >  <
     |___/\__\_\____|_|\__\___| |___/_/\_\\

     SQLite Extract Database schema tool 1.0
     ---
'''

    parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description='''
Simple tool for extract schema from
SQLite database.
    ''')

    maingroup = parser.add_argument_group(title='Required')
    optgroup = parser.add_argument_group(title='Optional')

    maingroup.add_argument('file',
                               help='input database filename')
    optgroup.add_argument('-d',
                    '--dump',
                    default=False,
                    help='''dump full database to file and sha1 file hash''',
                    action="store_true"
                    )
    optgroup.add_argument('-o',
                    '--output',
                    default=False,
                    help=''' save db_schema to file and sha1 file hash''',
                    action="store_true"
                    )
    optgroup.add_argument('-i',
                    '--info',
                    default=None,
                    help='''Info of SQLite tablename ''',
                    metavar='tablename'
                    )
    args = parser.parse_args()
    f_name = args.file

    if not os.path.exists(f_name):
        print '     The file {} does not exist!'.format(f_name)
        sys.exit(2)

    if not is_valid(f_name):
        print '     The file {} is not SQlite database!'.format(f_name)
        sys.exit(2)

    if (args.dump):
        to_sql(f_name)
        sys.exit(2)

    if (args.output):
        to_file(f_name, f_name)
        sys.exit(2)

    if (args.info):
        t_name = args.info
        get_metadata(f_name, t_name)
        sys.exit(2)

    to_stdout(get_sql_master(f_name))

if __name__ == "__main__":

    try:
        if len(sys.argv) > 1:
            main(sys.argv[1:])
        else:
            usage()
    except Exception, e:
        print "    Main Error_: "
        print ''
        import traceback
        print "    Error: %s" % e
        print "    {}".format(traceback.print_tb(sys.exc_info()[2]))
        print ''
