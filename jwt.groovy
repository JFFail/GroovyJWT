import groovy.json.JsonSlurper

// Function to create a JWT.
def CreateJWT(JsonSlurper slurper, Integer validSeconds, String appID, String tenantID, String appSecret, String iss) {
    // Get the Unix Epoch timestamp. In this case we need the original one and the expiration one.
    TimeZone.setDefault(TimeZone.getTimeZone('UTC'))
    def rightNowMilli = System.currentTimeMillis()
    def rightNowSec = Math.round(rightNowMilli / 1000)
    def expirationSec = rightNowSec + validSeconds

}

// Main code. Start with importing the endpoint information.
JsonSlurper slurper = new JsonSlurper()
def headersJson = slurper.parse(new File("./headers.json"))
def url = headersJson.URL

CreateJWT(slurper, 1800, headersJson.AppID, headersJson.TenantID, headersJson.AppSecret, headersJson.ISS)
