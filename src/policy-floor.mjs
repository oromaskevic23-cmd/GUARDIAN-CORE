import {DatabaseSync} from 'node:sqlite';
import {createHash,verify} from 'node:crypto';
import {policyBytes,evaluateSigned} from './signed-policy.mjs';
import {verifyVetoState} from './veto.mjs';
import {ensurePrivateDatabaseFile} from './secure-db.mjs';

const hash=x=>createHash('sha256').update(x).digest('hex');
const issuer=key=>hash(key.export({type:'spki',format:'der'}));
const sameKey=key=>key&&key.type==='public'&&key.asymmetricKeyType==='ed25519';

// Signed policy and veto snapshots advance together in one local transaction.
// The host must protect the database and pinned keys against replacement.
export class PolicyFloor {
  #db;
  constructor(path){
    ensurePrivateDatabaseFile(path);
    this.#db=new DatabaseSync(path);
    this.#db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS policy_floor (org TEXT PRIMARY KEY, policy_issuer TEXT NOT NULL, policy_epoch INTEGER NOT NULL, policy_iat INTEGER NOT NULL, policy_hash TEXT NOT NULL, veto_issuer TEXT NOT NULL, veto_epoch INTEGER NOT NULL, veto_iat INTEGER NOT NULL, veto_hash TEXT NOT NULL) STRICT;');
  }
  observe(policyEnvelope,vetoEnvelope,trust,now){
    try{
      const policy=structuredClone(policyEnvelope.payload),pSig=policyEnvelope.signature;
      const veto=structuredClone(vetoEnvelope),v=veto.payload;
      const bytes=policyBytes(policy),pKey=trust.policyKey,vKey=trust.vetoKey;
      if(!Number.isSafeInteger(now)||now<policy.iat||now>=policy.exp||policy.org!==trust.org||!Number.isSafeInteger(trust.minimumPolicyEpoch)||trust.minimumPolicyEpoch<0||policy.epoch<trust.minimumPolicyEpoch)return false;
      if(!sameKey(pKey)||!sameKey(vKey)||typeof pSig!=='string'||!/^[a-f0-9]{128}$/.test(pSig)||!verify(null,bytes,pKey,Buffer.from(pSig,'hex')))return false;
      if(!verifyVetoState(veto,vKey,trust.org,trust.minimumVetoEpoch,now))return false;
      const policyIssuer=issuer(pKey),vetoIssuer=issuer(vKey);
      const policyHash=hash(JSON.stringify(policy.rules.map(r=>[r.action,r.decision]).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0)));
      const vetoHash=hash(JSON.stringify([v.global,[...v.actions].sort()]));
      this.#db.exec('BEGIN IMMEDIATE');
      try{
        const old=this.#db.prepare('SELECT * FROM policy_floor WHERE org=?').get(trust.org);
        if(old&&(old.policy_issuer!==policyIssuer||old.veto_issuer!==vetoIssuer||policy.epoch<old.policy_epoch||v.epoch<old.veto_epoch||policy.iat<old.policy_iat||v.iat<old.veto_iat||(policy.epoch===old.policy_epoch&&policyHash!==old.policy_hash)||(v.epoch===old.veto_epoch&&vetoHash!==old.veto_hash))){this.#db.exec('ROLLBACK');return false;}
        this.#db.prepare('INSERT INTO policy_floor VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(org) DO UPDATE SET policy_issuer=excluded.policy_issuer,policy_epoch=excluded.policy_epoch,policy_iat=excluded.policy_iat,policy_hash=excluded.policy_hash,veto_issuer=excluded.veto_issuer,veto_epoch=excluded.veto_epoch,veto_iat=excluded.veto_iat,veto_hash=excluded.veto_hash').run(trust.org,policyIssuer,policy.epoch,policy.iat,policyHash,vetoIssuer,v.epoch,v.iat,vetoHash);
        this.#db.exec('COMMIT');return true;
      }catch(error){try{this.#db.exec('ROLLBACK');}catch{}throw error;}
    }catch{return false;}
  }
  evaluate(req,policy,veto,trust,now){
    try{
      const request=structuredClone(req),p=structuredClone(policy),v=structuredClone(veto);
      if(!this.observe(p,v,trust,now))return {decision:'DENY',reason:'STATE_NOT_ACCEPTED'};
      return evaluateSigned(request,p,v,trust,now);
    }catch{return {decision:'DENY',reason:'INVALID_INPUT'};}
  }
  close(){this.#db.close();}
}
