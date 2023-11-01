import argparse
import logging
import os
import sys

from ong_hue_api.hue import Hue
from ong_hue_api.internal_storage import KeyringStorage
from ong_hue_api.logs import create_logger
from ong_hue_api.utils import is_hdfs_s3

executable = "hue_api"


def create_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="""
        Api para realizar consultas impala vía HUE y descargarlas como ficheros. 
        Se crean tantos ficheros como consultas, del formato elegido (csv o xls). 
        Todos los ficheros se descargan en la carpeta elegida con el nombre que se indique, junto con un fichero de log.
        Después de descargar cada fichero se envia una notificación (salvo que se indique lo contrario)
        Nota: Hue está limitado a 1.000.000 filas, si necesitas más filas tendrás que dividir las consultas,
        usando limit y offset. 
        La primera vez que se ejecute (o cada vez que se cambie la contraseña) saltará una ventana para pedir contraseña.
        """,
        epilog=f"""
        Ejemplos de parámetros:
            {executable} -s "select * from tabla1" -s "select * from tabla2 where tabla2.campo in ('valor1', 'valor2')"
            Ejecuta las dos consultas y las guarda en los ficheros consulta1.csv y consulta2.csv de la carpeta actual
            {executable} -p="C:\\ejemplo de path" -s "select * from ejemplo"
            Ejecuta la consulta y la guarda en el fichero consulta1.csv en la carpeta c:\\ejemplo de consulta
            {executable} -q -s "select * from ejemplo"
            Ejecuta la consulta y la guarda en el fichero consulta1.csv de la carpeta actual sin enviar notificaciones
            {executable} -n "query de ejemplo" -s "select * from ejemplo"
            Ejecuta la consulta y la guarda en el fichero query de ejemplo.csv de la carpeta actual
            {executable} -f xls -n "query de ejemplo" -s "select * from ejemplo"
            Ejecuta la consulta y la guarda en el fichero query de ejemplo.xlsx de la carpeta actual
            {executable} -f xls -n "query de ejemplo" -s "select * from ejemplo" -s "select * from ejemplo2"
            Falla: hay que indicar tantos -n como -s
            {executable} -s "select * from table1" -c 10000   
            Ejecuta la consulta en trozos de 10.000 filas, ordenadas por el primer campo de la consulta
            {executable} -s "/dir1/dir2/filename"    
            Descarga el fichero hdfs filename en la carpeta actual
            {executable} -s "/dir1/dir2/filename1" -s "/dir1/dir2/filename2 -p c:\\"    
            Descarga los fichero hdfs filename1 y filename2 en la carpeta c:\\
            {executable} -s "select * from table1 where col1="${{param}}" -k param -v 12 -k param2 -v value2
            Descarga la consulta sustituyendo el parámetro param por el valor 12. Param2 se ignora

        """,
        # usage="uso"
    )

    parser.add_argument("-p", "--path", help="Directorio en el que se guardan los ficheros",
                        default=os.getcwd(), required=False)
    parser.add_argument("-u", "--user", help="Usuario",
                        default=None, required=False)
    parser.add_argument("-e", "--editor", help="HUE editor to use (Impala, Hive...)",
                        default="impala", required=False)
    parser.add_argument("-f", "--format", help="Formato de ficheros (csv o xls)",
                        default="csv", required=False, choices=['csv', 'xls'])
    parser.add_argument("-s", "--sql",
                        help="Query SQL entre comillas \" o path hdfs (si empieza por /) del fichero a descargar. "
                             "Usarlo tantas veces como sea necesario",
                        action="append",
                        required=True)
    parser.add_argument("-n", "--name", help="Nombre del fichero que se creará con la query SQL entre comillas \"",
                        action="append", required=False)
    parser.add_argument("-q", "--quiet", help="No enviar notificaciones (quiet)",
                        default=False, required=False, action="store_true")
    parser.add_argument("-c", "--chunksize", help="Filas en las que se dividirá la consulta (solo sql)",
                        default=None, required=False, type=int)
    parser.add_argument("-k", "--variable_key",
                        help="Nombre de parámetro para las consulta SQL. Aplica a todas las consultas",
                        required=False, action="append")
    parser.add_argument("-v", "--variable_value",
                        help="Valor de parámetro para las consulta SQL. Aplica a todas las consultas",
                        required=False, action="append")
    parser.add_argument("-d", "--debug",
                        help="Mostrar información de depuración",
                        required=False, action="store_true", default=False)
    return parser


def main():
    """Command line wrapper for ong_hue_api"""
    parser = create_parser()
    try:
        args = parser.parse_args(sys.argv[1:])
        logger = create_logger(args.path, level=logging.DEBUG if args.debug else logging.INFO)
        logger.debug(args)
    except SystemExit:
        parser.print_help()
        raise
    logger.info("Starting api with arguments: {}".format(" ".join(sys.argv)))
    names = args.name
    if names is None:
        names = [f"Consulta{i + 1}" for i in range(len(args.sql))]
    elif len(names) < len(args.sql):
        names = [f"{args.name[0]}{i + 1}" for i in range(len(args.sql))]
    kr = KeyringStorage(username=args.user, check=False)
    hue = Hue(show_notifications=not args.quiet, debug=args.debug, keyring_storage=kr,
              editor_type=args.editor)
    for sql, name in zip(args.sql, names):
        try:
            is_hdfs_s3(sql)     # Raises exception if not hdfs
            # Ignore filename when downloading hdfs/s3 files, uses remote filename
            hue.download_file(sql, local_filename=None, path=args.path)
        except ValueError:
            variables = None if not args.variable_key else \
                {k: v for k, v in zip(args.variable_key, args.variable_value)}

            hue.execute_query(sql, path=args.path, name=name, format=args.format,
                              chunk_rows=args.chunksize, variables=variables)


if __name__ == '__main__':
    sys.exit(main())
