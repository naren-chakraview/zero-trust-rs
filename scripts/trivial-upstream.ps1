$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:8080/")
$listener.Start()
Write-Output "trivial upstream listening on http://127.0.0.1:8080/"
while ($listener.IsListening) {
    $context = $listener.GetContext()
    $response = $context.Response
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("hello from the trivial upstream`n")
    $response.ContentType = "text/plain"
    $response.ContentLength64 = $bytes.Length
    $response.OutputStream.Write($bytes, 0, $bytes.Length)
    $response.OutputStream.Close()
}
