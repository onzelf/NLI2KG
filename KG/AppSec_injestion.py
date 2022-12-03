# the Python client for TypeDB
# https://github.com/vaticle/client-python
from typedb.client import TypeDB, TypeDBClient, SessionType, TransactionType

import csv
import sys, os, time

env_g = []
app_g = []

SERVER="127.0.0.1"
DATABASE="AppSec"

def build_AppSec_graph(inputs, data_path, keyspace_name):
    """
      gets the job done:
      1. creates a TypeDB instance
      2. creates a session to the targeted keyspace
      3. for each input:
        - a. constructs the full path to the data file
        - b. loads csv to TypeDB
      :param input as list of dictionaties: each dictionary contains details required to parse the data
    """
    with TypeDB.core_client(f"{SERVER}:1729") as client:  # 1
        with client.session(keyspace_name, SessionType.DATA) as session:  # 2
            for input in inputs:
                input["file"] = input["file"].replace(data_path, "")  # for testing purposes
                input["file"] = data_path + input["file"]  # 3a
                print("Loading from [" + input["file"] + ".csv] into TypeDB ...")
                load_data_into_typedb(input, session)  # 3b

def load_data_into_typedb(input, session):
    """
      loads the csv data into our TypeDB AppSec keyspace:
      1. gets the data items as a list of dictionaries
      2. for each item dictionary
        a. creates a TypeDB transaction
        b. constructs the corresponding TypeQL insert query
        c. runs the query
        d. commits the transaction
      :param input as dictionary: contains details required to parse the data
      :param session: off of which a transaction will be created
    """
    items = parse_data_to_dictionaries(input)  # 1

    count=0
    for item in items:  # 2
        count +=1
        with session.transaction(TransactionType.WRITE) as transaction:  # a
            graql_insert_query = input["template"](item)

            if isinstance(graql_insert_query, list):
                count -= 1
                for c,giq in enumerate(graql_insert_query):
                    print(c,type(giq)," Executing TypeQL Query: |" + giq+"|")
                    count += 1
                    transaction.query().insert(giq)  # c
                    transaction.commit()  # d
                    transaction = session.transaction(TransactionType.WRITE)
            else:
                print(type(graql_insert_query), "Executing TypeQL Query: " + graql_insert_query)
                transaction.query().insert(graql_insert_query)  # c
                transaction.commit()  # d


    print("\nInserted " + str(count) +
          " items from [ " + input["file"] + ".csv] into TypeDB.\n")


def app_template(app):
    app_g.append([app["id"],app["environmentId"]]) #build look-up table

    graql_insert_query  = 'insert $app isa app, has app_id "' + app["id"] + '"'
    graql_insert_query += ', has appRisk "' + app["appRisk"] + '"'
    if app["lastSeen"]: graql_insert_query += ', has lastSeen ' + app["lastSeen"][:-1]
    if app["startTime"]: graql_insert_query += ', has startTime ' + app["startTime"][:-1]
    graql_insert_query += ';'
    return graql_insert_query

def app_others_template(app_o):
    graql_insert_query = 'match $app isa app, has app_id "' + app_o["id"] + '";'
    graql_insert_query += 'insert $app has labels "' + app_o["labels_1"] + '"'
    #if app_o["labels_2"] != None :  graql_insert_query += ', has labels "' + app_o["labels_2"] + '"'
    #if app_o["labels_3"] != None :  graql_insert_query += ', has labels "' + app_o["labels_3"] + '"'

    graql_insert_query += ', has hostsName "' + app_o["hostsName_1"] + '"'
    if app_o["hostsName_2"] != "None" :  graql_insert_query += ', has hostsName "' + app_o["hostsName_2"] + '"'
    if app_o["hostsName_3"] != "None" :  graql_insert_query += ', has hostsName "' + app_o["hostsName_3"] + '"'

    graql_insert_query += ', has hostsIp "' + app_o["hostsIp_1"] + '"'
    if app_o["hostsIp_2"] != "None" :  graql_insert_query += ', has hostsIp "' + app_o["hostsIp_2"] + '"'
    if app_o["hostsIp_3"] != "None" :  graql_insert_query += ', has hostsIp "' + app_o["hostsIp_3"] + '"'
    graql_insert_query += ';'

    return graql_insert_query

def pod1_template(pod):
    graql_insert_query  = 'insert $pod isa pod, has pod_name "' + pod["pod_name"] +'";'
    return graql_insert_query

def pod2_template(pod):
    #graql_insert_query   = 'insert $pod isa pod, has pod_name "' + pod["pod_name"] + '"; '
    graql_insert_query = ' match $app isa app, has app_id "' + pod["id"] + '";'
    graql_insert_query += ' $pod isa pod, has pod_name "' + pod["pod_name"] + '"; '
    graql_insert_query += ' insert (has_pod:$pod, owner:$app) isa app_ownership; '
    print(">> ",graql_insert_query)
    return graql_insert_query

def env_template(env):
    #check if environment name has been already used
    if not env["id"] in env_g:
        env_g.append(env["id"])

    Target = [c for c,e in enumerate(app_g) if e[1]==env["id"]]
    print(env["id"],Target)
     
    Z=[]
    found=False
    for t in Target:
        if found:
            graql_insert_query  = 'match $0 isa app, has app_id "' + app_g[t][0] + '"; '
            graql_insert_query += '$x has env_id "' + env["id"] + '"; '
            graql_insert_query += ' insert  $x(contained-app:$0);'
        else:
            graql_insert_query = 'match $0 isa app, has app_id "' + app_g[t][0] + '";'
            graql_insert_query += ' insert  $x(contained-app:$0) isa environment; '
            graql_insert_query += '$x has env_id "' + env["id"] + '"; '
            graql_insert_query += '$x has env_name "' + env["name"] + '"; '
            graql_insert_query += '$x has env_risk "' + env["risk"] + '"; '
            found=True
        Z.append(graql_insert_query)
    return Z


def connection_template(connection):
    # match src
    graql_insert_query = 'match $0 isa app, has app_id  "' + connection["sourceId"] + '";'
    graql_insert_query += ' $1 isa app, has app_id "' + connection["destinationId"] + '";'
    graql_insert_query += ' insert $x(src: $0, dst: $1) isa connection; '
    graql_insert_query += ' $x has con_id "' + connection["id"] + '"; '
    graql_insert_query += ' $x has startTime ' + connection["startTime"][:-1] + '; '
    graql_insert_query += ' $x has protocol "' + connection["protocol"] + '"; '
    graql_insert_query += ' $x has destPort ' + connection["destinationPortNumber"] + '; '
    graql_insert_query += ' $x has numberOfConnections ' + connection["numberOfConnections"] +';'
    return graql_insert_query


def parse_data_to_dictionaries(input):
    """
      1. reads the file through a stream,
      2. adds the dictionary to the list of items
      :param input.file as string: the path to the data file, minus the format
      :returns items as list of dictionaries: each item representing a data item from the file at input.file
    """
    items = []
    with open(input["file"] + ".csv") as data:  # 1
        for row in csv.DictReader(data, skipinitialspace=True):
            item = {key: value for key, value in row.items()}
            items.append(item)  # 2
    return items


Inputs = [
    {
        "file": "app",
        "template": app_template
    },
    {
        "file": "env",
        "template": env_template
    },
    {
        "file": "connection",
        "template": connection_template
    }, 
    {
        "file": "app_others",
        "template": app_others_template
    },
    {
        "file": "app_others",
        "template": pod1_template
    },
    {
        "file": "app_others",
        "template": pod2_template
    }
]


def insertSchema(uri, database, force=False):

    if os.environ.get('https_proxy'):
        print("%%avoiding GRPC status 14 hack%%")
        del os.environ['https_proxy']
    if os.environ.get('http_proxy'):
        del os.environ['http_proxy']

    client = TypeDB.core_client(uri)

    if database in [db.name() for db in client.databases().all()]:
        if force:
            print("> database delete ",database)
            client.databases().get(database).delete()
        else:
            raise ValueError("database {} already exists, use --force True to overwrite")

    print("> database create ",database)
    client.databases().create(database)
    session = client.session(database, SessionType.SCHEMA)
    print('.....')
    print('>transaction {} schema write'.format(database))
    print('.....')
    with open("%s.gql"%database, "r") as typeql_file:
        schema = typeql_file.read()
        with session.transaction(TransactionType.WRITE) as write_transaction:
            write_transaction.query().define(schema)
            write_transaction.commit()
    print('.....')
    print('Success inserting schema: {}.gql'.format(database))
    print('.....')
    session.close()
    client.close()

if __name__ == "__main__":

    #insert schema
    insertSchema(f"{SERVER}:1729",DATABASE,force=True)

    # check/create directory
    dirName = 'datasets/'
    if os.path.isdir(dirName):
        print('Found directory /{}/'.format(dirName))
    else:
        print('FATAL: directory /{}/ not found'.format(dirName))
        sys.exit()

    build_AppSec_graph(inputs=Inputs, data_path=dirName, keyspace_name = DATABASE)
