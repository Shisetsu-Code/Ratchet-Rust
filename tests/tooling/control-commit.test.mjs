import {test} from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFile} from 'node:fs/promises';

test('an interrupted authority write cannot commit after recovery releases its fence',async()=>{
  const db=new DatabaseSync(':memory:');
  try{
    db.exec(await readFile('db/migrations/0001_ratchet_rust.sql','utf8'));
    db.exec("CREATE TABLE test_values(value TEXT); INSERT INTO authority_operations VALUES('cancelled','PENDING','now',NULL)");
    db.exec("UPDATE authority_operations SET status='ABORTED' WHERE operation_id='cancelled' AND status='PENDING'");
    assert.throws(()=>db.exec("BEGIN; INSERT INTO auth_commit_guards SELECT 'late',CASE WHEN EXISTS(SELECT 1 FROM authority_operations WHERE operation_id='cancelled' AND status='PENDING') THEN 1 ELSE 0 END; INSERT INTO test_values VALUES('should-not-commit'); UPDATE authority_operations SET status='COMMITTED' WHERE operation_id='cancelled'; COMMIT;"));
    db.exec('ROLLBACK');assert.equal(db.prepare('SELECT COUNT(*) AS n FROM test_values').get().n,0);
    db.exec("INSERT INTO authority_operations VALUES('completed','PENDING','now',NULL); BEGIN; INSERT INTO auth_commit_guards SELECT 'guard',CASE WHEN EXISTS(SELECT 1 FROM authority_operations WHERE operation_id='completed' AND status='PENDING') THEN 1 ELSE 0 END; INSERT INTO test_values VALUES('committed'); UPDATE authority_operations SET status='COMMITTED' WHERE operation_id='completed'; DELETE FROM auth_commit_guards WHERE assertion_id='guard'; COMMIT;");
    db.exec("UPDATE authority_operations SET status='ABORTED' WHERE operation_id='completed' AND status='PENDING'");
    assert.equal(db.prepare("SELECT status FROM authority_operations WHERE operation_id='completed'").get().status,'COMMITTED');
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM test_values').get().n,1);
  }finally{db.close();}
});
