import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {policyBytes} from '../src/signed-policy.mjs';
import {vetoBytes} from '../src/veto.mjs';
import {PolicyFloor} from '../src/policy-floor.mjs';
const p=generateKeyPairSync('ed25519'),v=generateKeyPairSync('ed25519'),other=generateKeyPairSync('ed25519');
const signed=(payload,bytes,key)=>({payload,signature:sign(null,bytes(payload),key.privateKey).toString('hex')});
const policy=(epoch=1,decision='ALLOW',iat=100,key=p)=>signed({v:1,org:'demo',epoch,iat,exp:iat+100,rules:[{action:'read',decision}]},policyBytes,key);
const veto=(epoch=1,global=false,iat=100,key=v)=>signed({v:1,org:'demo',epoch,iat,exp:iat+30,global,actions:[]},vetoBytes,key);
const trust={org:'demo',policyKey:p.publicKey,vetoKey:v.publicKey,minimumPolicyEpoch:1,minimumVetoEpoch:1};
const req={org:'demo',action:'read',identityVerified:true};
function fixture(fn){const d=mkdtempSync(join(tmpdir(),'policy-floor-'));try{fn(join(d,'floor.db'));}finally{rmSync(d,{recursive:true,force:true});}}

test('signed policy and veto decisions persist their floor',()=>fixture(path=>{
  let s=new PolicyFloor(path);try{assert.equal(s.evaluate(req,policy(2),veto(2,true),trust,120).reason,'ARCHITECT_VETO');}finally{s.close();}
  s=new PolicyFloor(path);try{assert.equal(s.evaluate(req,policy(1),veto(1),trust,120).decision,'DENY');assert.equal(s.evaluate(req,policy(2),veto(2,true),trust,120).reason,'ARCHITECT_VETO');}finally{s.close();}
}));
test('same epoch cannot silently relax signed veto or change policy',()=>fixture(path=>{
  const s=new PolicyFloor(path);try{assert.equal(s.observe(policy(1,'DENY'),veto(1,true),trust,120),true);assert.equal(s.observe(policy(1,'ALLOW'),veto(1,true),trust,120),false);assert.equal(s.observe(policy(1,'DENY'),veto(1,false),trust,120),false);assert.equal(s.observe(policy(2,'ALLOW',110),veto(2,false,110),trust,120),true);}finally{s.close();}
}));
test('tampered, expired or substituted authorities do not advance floor',()=>fixture(path=>{
  const s=new PolicyFloor(path);try{const fake=policy(5);fake.payload.rules[0].decision='DENY';assert.equal(s.observe(fake,veto(5),trust,120),false);assert.equal(s.observe(policy(1),veto(1),trust,130),false);assert.equal(s.observe(policy(1,'ALLOW',100,other),veto(1),trust,120),false);assert.equal(s.observe(policy(1),veto(1),trust,120),true);}finally{s.close();}
}));
test('policy and veto floors advance atomically',()=>fixture(path=>{
  const a=new PolicyFloor(path),b=new PolicyFloor(path);try{assert.equal(a.observe(policy(2),veto(2),trust,120),true);assert.equal(b.observe(policy(3,'ALLOW',110),veto(1),trust,120),false);assert.equal(b.observe(policy(2),veto(2),trust,120),true);}finally{a.close();b.close();}
}));
test('unverified identity is denied and key rotation is not automatic',()=>fixture(path=>{
  const s=new PolicyFloor(path);try{assert.equal(s.evaluate({...req,identityVerified:false},policy(),veto(),trust,120).decision,'DENY');const next={...trust,policyKey:other.publicKey};assert.equal(s.observe(policy(2,'ALLOW',110,other),veto(2,false,110),next,120),false);}finally{s.close();}
}));
test('memory storage is rejected',()=>{assert.throws(()=>new PolicyFloor(':memory:'));assert.throws(()=>new PolicyFloor('file::memory:?cache=shared'));});
test('failed floor write denies and rolls back both state changes',()=>fixture(path=>{
  const s=new PolicyFloor(path),db=new DatabaseSync(path);
  try{assert.equal(s.observe(policy(1),veto(1),trust,120),true);db.exec("CREATE TRIGGER reject_floor BEFORE UPDATE ON policy_floor BEGIN SELECT RAISE(ABORT,'failure'); END;");assert.equal(s.observe(policy(2,'ALLOW',110),veto(2,false,110),trust,120),false);db.exec('DROP TRIGGER reject_floor');assert.equal(s.observe(policy(1),veto(1),trust,120),true);}finally{db.close();s.close();}
}));
