package artifacts

import (
    "net/http/httptest"
    "net/url"
    "strings"
    "testing"
)

func TestLocalCIForwardCompatibleArtifactMetadata(t *testing.T) {
    body := `{"workflow_run_backend_id":"1","workflow_job_run_backend_id":"2","name":"test-output","version":4,"mime_type":"application/zip"}`
    request := httptest.NewRequest("POST", "/", strings.NewReader(body))
    response := httptest.NewRecorder()
    var parsed CreateArtifactRequest
    routes := &artifactV4Routes{}
    if !routes.parseProtbufBody(&ArtifactContext{Req:request, Resp:response}, &parsed) {
        t.Fatalf("metadata extension rejected: %d", response.Code)
    }
    if parsed.Name != "test-output" || parsed.WorkflowRunBackendId != "1" {
        t.Fatal("known fields were changed")
    }
    invalid := httptest.NewRequest("POST", "/", strings.NewReader(`{"version":"invalid"}`))
    if routes.parseProtbufBody(&ArtifactContext{Req:invalid, Resp:httptest.NewRecorder()}, &CreateArtifactRequest{}) {
        t.Fatal("invalid known field was accepted")
    }
}

// Azure core-client simpleParseQueryParams splits each pair on '=' and keeps
// only the first two pieces. Raw base64 padding is lost; percent encoding survives.
func TestLocalCISignedURLSurvivesAzureQueryParser(t *testing.T) {
    routes := &artifactV4Routes{prefix:ArtifactV4RouteBase, signingKey:[]byte("fixture-signing-key")}
    rawURL := routes.buildArtifactURL("localhost:34567", "UploadArtifact", "local proof", 1)
    parsed, err := url.Parse(rawURL)
    if err != nil { t.Fatal(err) }
    pairs := strings.Split(parsed.RawQuery, "&")
    for i, pair := range pairs {
        parts := strings.Split(pair, "=")
        pairs[i] = parts[0] + "=" + parts[1]
    }
    parsed.RawQuery = strings.Join(pairs, "&") + "&comp=block&blockid=fixture"
    request := httptest.NewRequest("PUT",parsed.String(),nil)
    task, name, ok := routes.verifySignature(&ArtifactContext{Req:request,Resp:httptest.NewRecorder()}, "UploadArtifact")
    if !ok || task != 1 || name != "local proof" { t.Fatal("valid signature did not survive Azure serialization") }
    query := parsed.Query()
    query.Set("artifactName","another-file")
    parsed.RawQuery = query.Encode()
    request = httptest.NewRequest("PUT",parsed.String(),nil)
    if _,_,ok := routes.verifySignature(&ArtifactContext{Req:request,Resp:httptest.NewRecorder()}, "UploadArtifact"); ok {
        t.Fatal("tampered artifact name accepted")
    }
}
