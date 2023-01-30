import json
import logging
import os
import requests

# Read environment variables
FILE_NAME = os.getenv("REPORT_FILE_DIRECTORY", "kube-bench-output.json")
NEW_RELIC_LICENCE_KEY = os.getenv("NEW_RELIC_LICENCE_KEY")
NEW_RELIC_SECURITY_DATA_API_URL = "https://security-api.newrelic.com/security/v1"
CLUSTER_NAME = os.getenv("CLUSTER_NAME", "minikube")


def main():
    if NEW_RELIC_LICENCE_KEY is None:
        print("Licence Key is not found! Set NEW_RELIC_LICENCE_KEY properly")
        exit(1)

    testDictionary = readTestDictionaryFromJSONFile(FILE_NAME)

    testListByCategory = testDictionary["Controls"]
    for testGroup in testListByCategory:
        section_id = testGroup["id"]
        version = testGroup["version"]
        detected_version = testGroup["detected_version"]
        text = testGroup["text"]
        node_type = testGroup["node_type"]

        for testSubSection in testGroup["tests"]:
            print(f'Sub Section Id, {testSubSection["section"]}')
            print(f'Description, {testSubSection["desc"]}')

            for testResult in testSubSection["results"]:
                status = testResult["status"]
                if status == "PASS":
                    continue
                test_number = testResult["test_number"]
                test_desc = testResult["test_desc"]
                remediation = testResult["remediation"]

                requestBody = getRequestBody(
                    version,
                    text,
                    node_type,
                    status,
                    test_number,
                    test_desc,
                    remediation,
                )
                requestHeaders = getRequestHeaders(NEW_RELIC_LICENCE_KEY)

                response = requests.post(
                    NEW_RELIC_SECURITY_DATA_API_URL,
                    json=requestBody,
                    headers=requestHeaders,
                )

                print("Response Status code: ", response.status_code)

                response_Json = response.json()
                print("Printing Post JSON data")
                print(response_Json)


def readTestDictionaryFromJSONFile(inputFileName: str):
    inputJsonFile = open(inputFileName)

    testDictionary = json.load(inputJsonFile)

    inputJsonFile.close()

    return testDictionary


def getRequestBody(
    version: str,
    text: str,
    node_type: str,
    status: str,
    test_number: str,
    test_desc: str,
    remediation: str,
):
    return {
        "findings": [
            {
                "source": "Kube Bench",
                "title": f"{version}-{test_number}",
                "message": test_desc,
                "issueType": "Host Vulnerability",
                "issueId": f"{version}-{test_number}",
                "severity": getSeverityByStatus(status),
                "remediationExists": "true",
                "remediationRecommendation": remediation,
                "entityType": "Kubernetes cluster",
                "entityLookupValue": CLUSTER_NAME,
            },
        ]
    }


def getSeverityByStatus(status: str):
    match status:
        case "FAIL":
            return "HIGH"

        case "WARN":
            return "MEDIUM"

        case "INFO":
            return "LOW"

        case "PASS":
            return "INFO"

        case _:
            logging.error(f"Test status: {status} is not in the defined list!")
            return ""


def getRequestHeaders(newRelicLicenceKey: str):
    return {"Content-type": "application/json", "Api-Key": newRelicLicenceKey}


main()
