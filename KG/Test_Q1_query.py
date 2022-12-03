"""
[NL: Which is the application with more connections? ]
"""
from typedb.client import TypeDB, TypeDBClient, SessionType, TransactionType

with TypeDB.core_client('localhost:1729') as client:
    with client.session("AppSec", SessionType.DATA) as session:
        with session.transaction(TransactionType.READ) as transaction:
            query = ['match',
                    ' $x1 isa app, has app_id $id1;',
                    ' (src:$x1, dst:$anyone) isa connection, has numberOfConnections $nc1;',
                    ' (contained-app:$x1) isa environment, has env_name $en1;',
                    ' max $nc1;  '
            ]
            print("\nQuery:\n", "\n".join(query))
            query = "".join(query)
            nc1 = transaction.query().match_aggregate(query).get().as_float()
            
            assert int(nc1)==34030913, f"expected 34030913 but find {nc1}"
            

            query = ['match',
                    ' $x1 isa app, has app_id $id1;',
                    ' (src:$x1, dst:$anyone) isa connection, has numberOfConnections '+str(nc1) +';',
                    ' (contained-app:$x1) isa environment, has env_name $en1;',
                    ' get $id1, $en1;  '
            ]
            query = "".join(query)

            iterator = transaction.query().match(query)
            answers = []
             
            for answer in iterator:
                answers.extend(answer.map().values())

            result = [ answer.get_value()  for answer in answers ]
            print("\nResult:\n", result)

            iterator = transaction.query().match(query)
            Var = ['id1','en1']
            for answer in iterator:
               print( "\n".join([v+": "+ str(answer.map().get(v).get_value()) for v in Var] ))
