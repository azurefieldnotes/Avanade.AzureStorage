
#region Helpers

Function SignRequestString
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$StringToSign,        
        [Parameter(Mandatory=$true)]
        [String]$SigningKey
    )

    $KeyBytes = [System.Convert]::FromBase64String($SigningKey)
    $HMAC = New-Object System.Security.Cryptography.HMACSHA256
    $HMAC.Key = $KeyBytes
    $UnsignedBytes = [System.Text.Encoding]::UTF8.GetBytes($StringToSign)
    $KeyHash = $HMAC.ComputeHash($UnsignedBytes)
    $SignedString=[System.Convert]::ToBase64String($KeyHash)
    Write-Output $SignedString
}

Function GetStringToSign
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('GET','PUT','DELETE')]
        [string]
        $Verb="GET",
        [Parameter(Mandatory=$true)]
        [datetime]
        $Date,
        [string]
        $TokenVersion = "2016-05-31",
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $Resource,
        [Parameter(Mandatory = $false)]
        [long]
        $ContentLength,        
        [Parameter(Mandatory = $false)]
        [String]
        $ContentLanguage,
        [Parameter(Mandatory = $false)]
        [String]
        $ContentEncoding,
        [Parameter(Mandatory = $false)]
        [String]
        $ContentType,
        [Parameter(Mandatory = $false)]
        [String]
        $ContentMD5,
        [Parameter(Mandatory = $false)]
        [int]
        $RangeStart,
        [Parameter(Mandatory = $false)]
        [int]
        $RangeEnd  
    )
    $AccessDate=$Date.ToString('R')
    $ResourceBase=($Resource.Host.Split('.') | Select-Object -First 1).TrimEnd("`0")
    $ResourcePath=$Resource.LocalPath.TrimStart('/').TrimEnd("`0")
    $LengthString=[String]::Empty
    $Range=[String]::Empty
    if($ContentLength -gt 0)
    {
        $LengthString="$ContentLength"
    }
    if($RangeEnd -gt 0)
    {
        $Range="bytes=$RangeStart-$RangeEnd"
    }
    
    $SigningPieces=@(
        $Verb,$ContentEncoding,
        $ContentLanguage,$LengthString,
        $ContentMD5,$ContentType,"","","","","",$Range,
        "x-ms-date:$AccessDate","x-ms-version:$TokenVersion","/$ResourceBase/$ResourcePath"
    )
    
    <#
    $SigningPieces=@($Verb.TrimEnd("`0"),"",
        "","","","","","","","","","",
        "x-ms-date:$($AccessDate.TrimEnd("`0"))","x-ms-version:$($TokenVersion.TrimEnd("`0"))","/$ResourceBase/$ResourcePath"
    )
    #>

    if ([String]::IsNullOrEmpty($Resource.Query) -eq $false)
    {
        $QueryResources=@{}
        $QueryParams=$Resource.Query.Substring(1).Split('&')
        foreach ($QueryParam in $QueryParams)
        {
            $ItemPieces=$QueryParam.Split('=')
            $ItemKey = ($ItemPieces|Select-Object -First 1).TrimEnd("`0")
            $ItemValue = ($ItemPieces|Select-Object -Last 1).TrimEnd("`0")
            if($QueryResources.ContainsKey($ItemKey))
            {
                $QueryResources[$ItemKey] = "$($QueryResources[$ItemKey]),$ItemValue"
            }
            else
            {
                $QueryResources.Add($ItemKey, $ItemValue)
            }
        }
        $Sorted=$QueryResources.Keys|Sort-Object
        foreach ($QueryKey in $Sorted)
        {
            $SigningPieces += "$($QueryKey):$($QueryResources[$QueryKey])"
        }
    }

    $StringToSign = [String]::Join("`n",$SigningPieces)
    Write-Output $StringToSign
}

Function InvokeAzureStorageRequest
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [Uri]$Uri,
        [Parameter(Mandatory=$true)]
        [System.Collections.IDictionary]$Headers
    )
    $Response=Invoke-WebRequest -Method Get -Uri $BlobUriBld.Uri -Headers $Headers -UseBasicParsing -ErrorAction Stop
    if ($Response -ne $null -and ([String]::IsNullOrEmpty($Response.Content) -eq $false))
    {
        #Really UTF-8 BOM???
        [Xml]$Result=$Response.Content.Substring(3)
        Write-Output $Result    
    }
}

Function DownloadBlob
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$Uri,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]
        $Destination,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]
        $BufferSize = 4096
    )
    $ResponseStream = [System.IO.Stream]::Null
    $OutputStream = [System.IO.Stream]::Null
    $Activity="Downloading $(Split-Path -Path $Destination -Leaf)"
    $WebRequest = [System.Net.WebRequest]::Create($Uri)
    if ($Headers -ne $null -and $Headers.Count -gt 0)
    {
        foreach ($HeaderName in $Headers.Keys)
        {
            $WebRequest.Headers.Add($HeaderName, $Headers[$HeaderName])
        }
    }
    $Stopwatch=New-Object System.Diagnostics.Stopwatch
    try
    {
        #Get a content length for progress....
        Write-Progress -Activity $Activity -Status "Contacting $($Uri.AbsoluteUri)" -PercentComplete 0
        Write-Verbose "$Activity - Contacting $($Uri.AbsoluteUri)"
        $WebResponse = $WebRequest.GetResponse()
        $TotalSize=$WebResponse.ContentLength
        $ContentType=$WebResponse.ContentType
        $Stopwatch.Start()
        Write-Progress -Activity $Activity -Status "Status:$($WebResponse.StatusCode) $ContentType Response of $($TotalSize/1MB)" -PercentComplete 0
        Write-Verbose "$Activity - Status:$($WebResponse.StatusCode) $ContentType Response of $($TotalSize/1MB)"
        $ResponseStream = $WebResponse.GetResponseStream()
        $OutputStream = [System.IO.File]::OpenWrite($Destination)
        $ReadBuffer = New-Object Byte[]($BufferSize)
        $BytesWritten=0
        $BytesRead = $ResponseStream.Read($ReadBuffer, 0, $BufferSize)
        $BytesWritten+=$BytesRead
        $Activity="$Activity $($TotalSize/1MB)mb"
        while ($BytesRead -gt 0)
        {
            $OutputStream.Write($ReadBuffer, 0, $BytesRead)
            $BytesRead = $ResponseStream.Read($ReadBuffer, 0, $BufferSize)
            $BytesWritten+=$BytesRead
            $Speed=$(($BytesWritten/1MB)/$Stopwatch.Elapsed.Seconds)
            Write-Verbose "$Activity - Writing Response $ContentType $(Split-Path -Path $Destination -Leaf)`t-`t$BytesWritten"
            Write-Progress -Activity $Activity -Status "Response $ContentType $(Split-Path -Path $Destination -Leaf) $BytesWritten bytes written -`t($Speed mb/s)" `
                -PercentComplete $(($BytesWritten/$TotalSize) * 100)
        }
    }
    catch [System.Net.WebException], [System.Exception]
    {
        throw $_
    }
    finally
    {
        $Stopwatch.Stop()
        if ($OutputStream -ne $null)
        {
            $OutputStream.Dispose()
        }
        if ($ResponseStream -ne $null)
        {
            $ResponseStream.Dispose()
        }
        Write-Progress -Activity $Activity -Completed
    }
}

Function UploadBlob
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$Uri,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]
        $SourceFile,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]
        $BufferSize = 4096
    )

    try
    {
        
    }
    catch [System.Net.WebException], [System.Exception]
    {
        throw $_
    }
    finally
    {
        
    }
}


#endregion

Function New-SASToken
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('GET','PUT','DELETE')]
        [string]
        $Verb="GET",
        [Parameter(Mandatory=$false)]
        [datetime]
        $Date=([System.DateTime]::UtcNow),
        [string]
        $TokenVersion = "2016-05-31",
        [Parameter(Mandatory=$true)]
        [System.Uri]
        $Resource,
        [Parameter(Mandatory = $false)]
        [long]
        $ContentLength,        
        [Parameter(Mandatory = $false)]
        [String]
        $ContentLanguage,
        [Parameter(Mandatory = $false)]
        [String]
        $ContentEncoding,
        [Parameter(Mandatory = $false)]
        [String]
        $ContentType,
        [Parameter(Mandatory = $false)]
        [String]
        $ContentMD5,
        [Parameter(Mandatory = $false)]
        [int]
        $RangeStart,
        [Parameter(Mandatory = $false)]
        [int]
        $RangeEnd,
        [Parameter(Mandatory=$true)]
        [string]
        $AccessKey     
    )
    $StringToSign=GetStringToSign -Verb GET -Date $Date -TokenVersion $TokenVersion -Resource $Resource `
        -ContentLength $ContentLength -ContentLanguage $ContentLanguage -ContentEncoding $ContentEncoding `
        -ContentType $ContentType -ContentMD5 $ContentMD5 -RangeStart $RangeStart -RangeEnd $RangeEnd
    $SharedAccessSignature=SignRequestString -StringToSign $StringToSign -SigningKey $AccessKey
    Write-Output $SharedAccessSignature
}

Function Get-BlobContainerMetadata
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$ContainerName,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$StorageAccountDomain="blob.core.windows.net",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$AccessKey,
        [Parameter(Mandatory=$false)]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ApiVersion="2016-05-31"
    )
    $BlobFQDN="https://$StorageAccountName.$StorageAccountDomain"
    #Build the uri..
    if($UseHttp.IsPresent)
    {
        $BlobFQDN="http://$StorageAccountName.$StorageAccountDomain"
    }
    $BlobUriBld=New-Object System.UriBuilder($BlobFQDN)
    $BlobUriBld.Path="$ContainerName"
    $BlobUriBld.Query="restype=container&comp=metadata"
    $AccessDate=[DateTime]::UtcNow
    $SasToken=New-SASToken -Verb GET -Date $AccessDate -Resource $BlobUriBld.Uri -AccessKey $AccessKey
    $BlobHeaders= @{
        "x-ms-date"=$AccessDate.ToString('R');
        "x-ms-version"=$ApiVersion;
        "Authorization"="SharedKey $($StorageAccountName):$($SasToken)"
    }
    $Result=InvokeAzureStorageRequest -Uri $BlobUriBld.Uri -Headers $BlobHeaders
    Write-Output $Result
}

Function Get-BlobContainerContents
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ContainerName='$root',
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$StorageAccountDomain="blob.core.windows.net",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$AccessKey,
        [Parameter(Mandatory=$false)]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ApiVersion="2016-05-31"
    )
    $BlobFQDN="https://$StorageAccountName.$StorageAccountDomain"
    #Build the uri..
    if($UseHttp.IsPresent)
    {
        $BlobFQDN="http://$StorageAccountName.$StorageAccountDomain"
    }
    Write-Verbose "[Get-BlobContainerContents] Creating SAS Token for $($BlobUriBld.Uri)"
    $BlobUriBld=New-Object System.UriBuilder($BlobFQDN)
    $BlobUriBld.Path="$ContainerName"
    $BlobUriBld.Query="restype=container&comp=list"
    $AccessDate=[DateTime]::UtcNow
    $SasToken=New-SASToken -Verb GET -Date $AccessDate -Resource $BlobUriBld.Uri -AccessKey $AccessKey
    $BlobHeaders= @{
        "x-ms-date"=$AccessDate.ToString('R');
        "x-ms-version"=$ApiVersion;
        "Authorization"="SharedKey $($StorageAccountName):$($SasToken)"
    }
    $BlobResult=InvokeAzureStorageRequest -Uri $BlobUriBld.Uri -Headers $BlobHeaders|Select-Object -ExpandProperty EnumerationResults
    Write-Verbose "[Get-BlobContainerContents] Blob Response Endpoint:$($BlobResult.ServiceEndpoint) container $($BlobResult.ContainerName)"
    if($BlobResult.Blobs -ne $null)
    {
        foreach ($Blob in $BlobResult.Blobs.Blob)
        {
            Write-Output $Blob
        }
    }
}

Function Get-AzureStorageBlob
{
    [CmdletBinding(DefaultParameterSetName='default')]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='public')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='default')]
        [Uri[]]$Uri,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='public')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='default')]
        [string]$Destination=$env:TEMP,        
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='default')]
        [String]$AccessKey,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='public')]
        [Switch]$IsPublic,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='default')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='public')]
        [String]$ApiVersion="2016-05-31"
    )
    BEGIN
    {
        
    }
    PROCESS
    {
        foreach ($item in $collection)
        {
            $StorageAccountName=$($item.Host.Split('.')|Select-Object -First 1)
            $DestinationFile=Join-Path $Destination $(Split-Path $item -Leaf)
            Write-Verbose "[Get-AzureStorageBlob] Requesting Azure Storage Blob $item from Storage Account:$StorageAccountName"
            $RequestParams=@{
                Uri=$item;
                Destination=$DestinationFile;
            }
            if ($PSCmdlet.ParameterSetName -eq 'default')
            {
                $AccessDate=[DateTime]::UtcNow
                $SasToken=New-SASToken -Verb GET `
                    -Date $AccessDate -TokenVersion $ApiVersion `
                    -Resource $item -AccessKey $AccessKey
                $RequestParams.Add('Headers',@{
                    'x-ms-date'=$AccessDate.ToString('R');
                    'x-ms-version'=$ApiVersion;
                    'Authorization'="SharedKey $($StorageAccountName):$($SasToken)"
                })
                Write-Verbose "[Get-AzureStorageBlob] Using SharedKey $SasToken"
            }
            DownloadBlob @RequestParams
        }
    }
}