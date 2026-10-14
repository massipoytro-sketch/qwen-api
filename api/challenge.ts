import { z } from "zod";
import { supabase } from "../src/db/supabase";
import { hashValue } from "../src/security/utils";
import { checkRateLimit } from "../src/security/rateLimit";
import { issueSecurityChallenge, consumeSecurityChallenge } from "../src/security/challenge";
import { verifyAndConsumeRequestSignature } from "../src/security/requestSigning";
import { securityLog } from "../src/security/observability";

const bodySchema = z.discriminatedUnion("mode", [
  z.object({ mode: z.literal("issue"), tenantId: z.uuid(), subjectId: z.uuid().optional(), sessionId: z.uuid().optional(), challengeType: z.enum(["step_up_mfa","proof_of_work","risk_based_verification"]), reasonCodes: z.array(z.string().max(100)).max(32).default([]), ttlSeconds: z.number().int().min(30).max(900).default(300) }).strict(),
  z.object({ mode: z.literal("consume"), tenantId: z.uuid(), token: z.string().min(32).max(128) }).strict(),
]);
const json=(body:unknown,status=200,requestId?:string)=>new Response(JSON.stringify(body),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff","x-frame-options":"DENY",...(requestId?{"x-request-id":requestId}:{})}});
export default async function handler(request:Request){
 const candidate=request.headers.get("x-request-id")??"";const requestId=/^[A-Za-z0-9._:-]{1,100}$/.test(candidate)?candidate:crypto.randomUUID();
 if(request.method!=="POST")return json({error:"METHOD_NOT_ALLOWED",requestId},405,requestId);
 const bearer=/^Bearer\s+(.+)$/i.exec(request.headers.get("authorization")??"");if(!bearer||bearer[1].length>512)return json({error:"UNAUTHORIZED",requestId},401,requestId);const apiKey=bearer[1].trim();
 try{
  const rawBody=await request.text();if(new TextEncoder().encode(rawBody).byteLength>16*1024)return json({error:"PAYLOAD_TOO_LARGE",requestId},413,requestId);
  const body=bodySchema.parse(JSON.parse(rawBody));
  const tenant=await supabase.schema("security").from("tenants").select("id,status").eq("id",body.tenantId).eq("api_key_hash",hashValue(apiKey)).maybeSingle();if(tenant.error)throw tenant.error;if(!tenant.data||tenant.data.status!=="active")return json({error:"UNAUTHORIZED",requestId},401,requestId);
  const signature=await verifyAndConsumeRequestSignature({request,rawBody,apiKey,tenantId:tenant.data.id});if(!signature.valid)return json({error:"INVALID_REQUEST_SIGNATURE",requestId},401,requestId);
  const limit=await checkRateLimit({tenantId:body.tenantId,key:`challenge:${hashValue(apiKey)}`,bucket:"challenge",limit:30,windowSeconds:60});if(!limit.allowed)return json({error:"RATE_LIMITED",retryAfter:Math.max(1,Math.ceil((Date.parse(limit.resetAt)-Date.now())/1000)),requestId},429,requestId);
  if(body.mode==="issue")return json({...await issueSecurityChallenge(body),requestId},201,requestId);
  const result=await consumeSecurityChallenge(body.token);if(result.tenantId!==body.tenantId)return json({valid:false,reasonCode:"CHALLENGE_TENANT_MISMATCH",requestId},403,requestId);return json({...result,requestId},result.valid?200:409,requestId);
 }catch(error){if(error instanceof z.ZodError||error instanceof SyntaxError)return json({error:"INVALID_REQUEST",requestId},400,requestId);securityLog("challenge_api_error",{requestId,errorCode:error instanceof Error?error.name:"UNKNOWN_ERROR"});return json({error:"INTERNAL_ERROR",requestId},500,requestId);}
}
