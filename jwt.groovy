import groovy.json.JsonOutput
import groovy.json.JsonSlurper

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
    def headerBase64 = headerJson.bytes.encodeBase64().toString().split("=")[0].replaceAll("\\+", "-").replaceAll("/", "_")
    def payloadBase64 = payloadJson.bytes.encodeBase64().toString().split("=")[0].replaceAll("\\+", "-").replaceAll("/", "_")
}

// Main code. Start with importing the endpoint information.
JsonSlurper slurper = new JsonSlurper()
def headersJson = slurper.parse(new File("./headers.json"))
def url = headersJson.URL

createJWT(slurper, 1800, headersJson.AppID, headersJson.TenantID, headersJson.AppSecret, headersJson.ISS)
