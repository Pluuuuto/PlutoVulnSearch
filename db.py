import psycopg2
import configparser

def connect_db(config_file='db_config.ini'):
    config = configparser.ConfigParser()
    config.read(config_file)
    return psycopg2.connect(**config['postgresql'])
