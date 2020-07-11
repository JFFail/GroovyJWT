import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Mac

// Function to create a JWT.
def createJWT(JsonSlurper slurper, Integer validSeconds, String appID, String tenantID, String appSecret, String iss) {
    // Get the Unix Epoch timestamp. In this case we need the original one and the expiration one.
    TimeZone.setDefault(TimeZone.getTimeZone('UTC'))
    def rightNowMilli = System.currentTimeMillis()
    def rightNowSec = Math.round(rightNowMilli / 1000)
    def expirationSec = rightNowSec + validSeconds
    
    // Create a UUID to pass with the token. Avoids replay attacks.
    def jtiValue = UUID.randomUUID().toString()

    // Create maps for the header and payload.
    Map header = [alg: "HS256", typ: "JWT"]
    Map payload = [exp: expirationSec, iat: rightNowSec, iss: iss, sub: appID, tid: tenantID, jti: jtiValue]

    // Convert the maps to JSON.
    def headerJson = JsonOutput.toJson(header)
    def payloadJson = JsonOutput.toJson(payload)

    // Convert the header and payload to Base64.
    def headerBase64 = headerJson.getBytes("UTF-8").encodeBase64().toString().split("=")[0].replaceAll("\\+", "-").replaceAll("/", "_")
    def payloadBase64 = payloadJson.getBytes("UTF-8").encodeBase64().toString().split("=")[0].replaceAll("\\+", "-").replaceAll("/", "_")

    // Sign the header + payload combination.
    def toBeSigned = headerBase64 + "." + payloadBase64
    SecretKeySpec secretKeySpec = new SecretKeySpec(appSecret.getBytes("UTF-8"), "HmacSHA256")
    Mac mac = Mac.getInstance("HmacSHA256")
    mac.init(secretKeySpec)
    byte[] digest = mac.doFinal(toBeSigned.getBytes("UTF-8"))
    def signature = digest.encodeBase64().toString().split("=")[0].replaceAll("\\+", "-").replaceAll("/", "_")

    // Put it all together for the token.
    def token = headerBase64 + "." + payloadBase64 + "." + signature
    token
}

// Main code. Start with importing the endpoint information.
JsonSlurper slurper = new JsonSlurper()
def headersJson = slurper.parse(new File("./headers.json"))
def url = headersJson.URL

// Create the JWT.
def jwt = createJWT(slurper, 1800, headersJson.AppID, headersJson.TenantID, headersJson.AppSecret, headersJson.ISS)

// Bundle the JWT into JSON for the payload.
Map payloadMap = [auth_token: jwt]
def payloadJson = JsonOutput.toJson(payloadMap)

// Make a connection and pass the JWT for an access token.
def conn = new URL(url).openConnection()
conn.setReadTimeout(1500)
conn.setRequestMethod("POST")
conn.setRequestProperty("Accept", "*/*")
conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
conn.doOutput = true

// Create a writer needed to POST..
def writer = new OutputStreamWriter(conn.outputStream)
writer.write(payloadJson)
writer.flush()
writer.close()
conn.connect()

// Check the response and just print if 200.
def responseCode = conn.getResponseCode()
if( responseCode == 200 ) {
    def responseText = conn.content.text
    println responseText
    conn.disconnect()
} else {
    println "ERROR with the HTTP call. Response code was $responseCode."
    conn.disconnect()
}
