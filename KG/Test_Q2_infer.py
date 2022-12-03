from typedb.client import * #TypeDB, TypeDBClient, SessionType, TransactionType
import sys

 
if len(sys.argv) > 1 :
    infer = False
    print("MESSAGE: Testing with inference disabled")
else:
    infer = True
    print("MESSAGE: Testing with inference enabled")
    
    
with TypeDB.core_client('localhost:1729') as client:
    with client.session("AppSec", SessionType.DATA) as session:
        opts = TypeDBOptions.core()
        opts.infer = infer
        with session.transaction(TransactionType.READ, opts) as tx:
            query = ['match',
                     ' $x1 isa app, has app_id $y1;',
                     ' (contained-app:$x1) isa environment, has env_name "Prod";',
                     ' $x3 isa app, has app_id $y3;',
                     ' (contained-app:$x3) isa environment, has env_name "Finance";',
                     ' (src:$x1, dst:$x3) isa connection; '
            ]
            print("\nQuery:\n", "\n".join(query))
            query = "".join(query)
            answers = tx.query().match(query)
            entities = []

            e={}
            var=["y1", "y3"]
            for n,concept in enumerate(answers):
                for v in  var:
                    thing = concept.get(v)
                    e = {f"{thing.get_type().get_label()}_{v}": f"{thing.get_value()}"}
                    entities.append(e)
            if infer:
                assert len(entities)==6, f"expecting 6 entities, found {len(entities)}"
            else:
                assert len(entities)==2, f"expecting 6 entities, found {len(entities)}"
            print("\n".join([str(e)+" -> "+str(entities[c+1]) for c,e in enumerate(entities) if c%2==0]))
