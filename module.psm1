
$Script:UTF8ByteOrderMark=[System.Text.Encoding]::Default.GetString([System.Text.Encoding]::UTF8.GetPreamble())

#region Helpers

Function SignRequestString
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName=$true)]
        [String]$StringToSign,        
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$SigningKey
    )
    PROCESS
    {
        $KeyBytes = [System.Convert]::FromBase64String($SigningKey)
        $HMAC = New-Object System.Security.Cryptography.HMACSHA256
        $HMAC.Key = $KeyBytes
        $UnsignedBytes = [System.Text.Encoding]::UTF8.GetBytes($StringToSign)
        $KeyHash = $HMAC.ComputeHash($UnsignedBytes)
        $SignedString=[System.Convert]::ToBase64String($KeyHash)
        Write-Output $SignedString        
    }
}

Function GetTokenStringToSign
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('GET','PUT','DELETE')]
        [string]
        $Verb="GET",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]
        $Resource,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [long]
        $ContentLength,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $ContentLanguage,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $ContentEncoding,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $ContentType,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $ContentMD5,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]
        $RangeStart,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]
        $RangeEnd,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [System.Collections.IDictionary]
        $Headers
    )
    PROCESS
    {
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
            $ContentMD5,$ContentType,"","","","","",$Range
        )
        foreach ($item in $Headers.Keys)
        {
            $SigningPieces+="$($item):$($Headers[$item])"
        }
        $SigningPieces+="/$ResourceBase/$ResourcePath"

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
}

Function InvokeAzureStorageRequest
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [Uri]$Uri,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]
        $Method = "GET",
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [System.Object]
        $Body, 
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]
        $ReturnHeaders
    )

    PROCESS
    {
        $RequestParams=@{
            Method=$Method;
            Uri=$Uri;
            Headers=$Headers;
            UseBasicParsing=$true;
            ErrorAction='Stop'
        }
        if($Body -ne $null)
        {
            $RequestParams.Add('Body',$Body)
        }
        $Response=Invoke-WebRequest @RequestParams
        if($Response -ne $null)
        {
            if($ReturnHeaders.IsPresent -and $Response.Headers -ne $null)
            {
                Write-Output $Response.Headers
            }
            elseif ([String]::IsNullOrEmpty($Response.Content) -eq $false)
            {
                $ResultString=$Response.Content
                if($ResultString.StartsWith($Script:UTF8ByteOrderMark,[System.StringComparison]::Ordinal))
                {
                    #Really UTF-8 BOM???
                    $ResultString=$ResultString.Remove(0,$Script:UTF8ByteOrderMark.Length)
                }
                [Xml]$Result=$ResultString
                Write-Output $Result
            }
        }
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('GET','PUT','DELETE')]
        [string]
        $Verb="GET",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [System.Uri]
        $Resource,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [long]
        $ContentLength,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [String]
        $ContentLanguage,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [String]
        $ContentEncoding,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [String]
        $ContentType,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [String]
        $ContentMD5,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [int]
        $RangeStart,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [int]
        $RangeEnd,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]
        $AccessKey,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName=$true)]
        [System.Collections.IDictionary]
        $Headers
    )
    PROCESS
    {
        $SigningElements=@{
            Verb=$Verb;
            Resource=$Resource;
            ContentLength=$ContentLength;
            ContentLanguage=$ContentLanguage;
            ContentEncoding=$ContentEncoding;
            ContentType=$ContentType;
            RangeStart=$RangeStart;
            RangeEnd=$RangeEnd;
            Headers=$Headers;
        }
        $StringToSign = GetTokenStringToSign @SigningElements
        Write-Verbose "[New-SASToken] String to Sign:$StringToSign"
        $SharedAccessSignature=SignRequestString -StringToSign $StringToSign -SigningKey $AccessKey
        Write-Output $SharedAccessSignature        
    }
}

Function Get-AzureBlobContainerMetadata
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
    $AccessDate = [DateTime]::UtcNow
    $BlobFQDN="https://$StorageAccountName.$StorageAccountDomain"
    #Build the uri..
    if($UseHttp.IsPresent)
    {
        $BlobFQDN="http://$StorageAccountName.$StorageAccountDomain"
    }
    $BlobUriBld=New-Object System.UriBuilder($BlobFQDN)
    $BlobUriBld.Path="$ContainerName"
    $BlobUriBld.Query="restype=container&comp=metadata"
    $RequestParams=@{
        Method='Get';
        Uri=$BlobUriBld.Uri;
        ReturnHeaders=$true;
    }
    $BlobHeaders= @{
        "x-ms-date"=$AccessDate.ToString('R');
        "x-ms-version"=$ApiVersion;
    }
    $SasToken=New-SASToken -Verb GET -Resource $BlobUriBld.Uri -AccessKey $AccessKey -Headers $BlobHeaders
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result=InvokeAzureStorageRequest @RequestParams
    Write-Output $Result
}

Function Set-AzureBlobContainerMetadata
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$ContainerName,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "blob.core.windows.net",
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.Collections.IDictionary]$Metadata,
        [Parameter(Mandatory = $false)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )
    $BlobFQDN = "https://$StorageAccountName.$StorageAccountDomain"
    #Build the uri..
    if ($UseHttp.IsPresent)
    {
        $BlobFQDN = "http://$StorageAccountName.$StorageAccountDomain"
    }
    $BlobUriBld = New-Object System.UriBuilder($BlobFQDN)
    $BlobUriBld.Path = "$ContainerName"
    $BlobUriBld.Query = "restype=container&comp=metadata"
    $RequestParams=@{
        Method='PUT';
        Uri=$BlobUriBld.Uri;
        ReturnHeaders=$true;
    }    
    $BlobHeaders = [ordered]@{
        "x-ms-date" = [DateTime]::UtcNow.ToString('R');
    }
    foreach($MetaKey in ($Metadata.Keys|Sort-Object))
    {
        $BlobHeaders.Add("x-ms-meta-$MetaKey",$Metadata[$MetaKey])
    }
    $BlobHeaders.Add("x-ms-version",$ApiVersion)
    $SasToken=New-SASToken -Verb PUT -Resource $BlobUriBld.Uri -AccessKey $AccessKey -Headers $BlobHeaders
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result = InvokeAzureStorageRequest @RequestParams
}

Function Get-AzureBlobContainerBlobs
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
    $BlobUriBld=New-Object System.UriBuilder($BlobFQDN)
    $BlobUriBld.Path="$ContainerName"
    $BlobUriBld.Query="restype=container&comp=list"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='Get';
    }
    Write-Verbose "[Get-AzureBlobContainerBlobs] Creating SAS Token for $($BlobUriBld.Uri)"
    $BlobHeaders= @{
        "x-ms-date"=[DateTime]::UtcNow.ToString('R');
        "x-ms-version"=$ApiVersion;
    }
    $SasToken=New-SASToken -Verb GET -Resource $BlobUriBld.Uri -AccessKey $AccessKey -Headers $BlobHeaders
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $BlobResult=InvokeAzureStorageRequest @RequestParams|Select-Object -ExpandProperty EnumerationResults
    Write-Verbose "[Get-AzureBlobContainerBlobs] Blob Response Endpoint:$($BlobResult.ServiceEndpoint) container $($BlobResult.ContainerName)"
    if ($BlobResult -ne $null -and  $BlobResult.Blobs -ne $null)
    {
        foreach ($Blob in $BlobResult.Blobs.Blob)
        {
            Write-Output $Blob
        }
    }
}

Function Copy-AzureBlob
{
    [CmdletBinding(DefaultParameterSetName='default')]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName='wordy')]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ParameterSetName='wordy')]
        [String]$StorageAccountDomain = "blob.core.windows.net",
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ParameterSetName='wordy')]
        [String]$ContainerName='$root',
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ParameterSetName='wordy')]
        [String]$BlobName = '$root',
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='public')]
        [Parameter(Mandatory =$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName = $true,ParameterSetName='default')]
        [Uri[]]$Uri,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='public')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='default')]
        [string]$Destination=$env:TEMP,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName='wordy')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='default')]
        [String]$AccessKey,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='public')]
        [Switch]$IsPublic,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='default')]
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ParameterSetName='wordy')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='public')]
        [String]$ApiVersion="2016-05-31"
    )
    BEGIN
    {
        
    }
    PROCESS
    {
        if($PSCmdlet.ParameterSetName -eq 'wordy')
        {
            $Uri=@(New-Object Uri("https://$StorageAccountName.$StorageAccountDomain/$ContainerName/$BlobName"))
        }
        foreach ($item in $Uri)
        {
            if([String]::IsNullOrEmpty($StorageAccountName))
            {
                $StorageAccountName=$($item.Host.Split('.')|Select-Object -First 1)                
            }
            $DestinationFile=Join-Path $Destination $(Split-Path $item -Leaf)
            Write-Verbose "[Copy-AzureBlob] Requesting Azure Storage Blob $item from Storage Account:$StorageAccountName"
            $RequestParams=@{
                Uri=$item;
                Destination=$DestinationFile;
            }
            if ($PSCmdlet.ParameterSetName -in 'default','wordy')
            {
                $BlobHeaders=@{
                    'x-ms-date'=[DateTime]::UtcNow.ToString('R');
                    'x-ms-version'=$ApiVersion;
                }
                $SasToken=New-SASToken -Verb GET -Resource $item -AccessKey $AccessKey -Headers $BlobHeaders
                $BlobHeaders.Add('Authorization',"SharedKey $($StorageAccountName):$($SasToken)")
                $RequestParams.Add('Headers',$BlobHeaders)
                Write-Verbose "[Copy-AzureBlob] Using SharedKey $SasToken"
            }
            DownloadBlob @RequestParams
        }
    }
}

Function Get-AzureBlobContainer
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "blob.core.windows.net",
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )

    $AccessDate = [DateTime]::UtcNow
    $BlobFQDN = "https://$StorageAccountName.$StorageAccountDomain"
    #Build the uri..
    if ($UseHttp.IsPresent)
    {
        $BlobFQDN = "http://$StorageAccountName.$StorageAccountDomain"
    }
    $BlobUriBld = New-Object System.UriBuilder($BlobFQDN)
    $BlobUriBld.Query = "comp=list"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='GET';
    }
    $BlobHeaders = @{
        "x-ms-date" = $AccessDate.ToString('R');
        "x-ms-version" = $ApiVersion;
    }
    $SasToken = New-SASToken -Verb GET -Resource $BlobUriBld.Uri -AccessKey $AccessKey -Headers $BlobHeaders
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result = InvokeAzureStorageRequest @RequestParams|Select-Object -ExpandProperty EnumerationResults
    Write-Verbose "[Get-AzureBlobContainer] Blob Response Endpoint:$($Result.ServiceEndpoint)"
    if($Result -ne $null -and $Result.Containers -ne $null)
    {
        foreach ($item in $Result.Containers.Container)
        {
            Write-Output $item
        }
    }
}

Function Get-AzureBlobServiceProperties
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "blob.core.windows.net",
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )

    $AccessDate = [DateTime]::UtcNow
    $BlobFQDN = "https://$StorageAccountName.$StorageAccountDomain"
    #Build the uri..
    if ($UseHttp.IsPresent)
    {
        $BlobFQDN = "http://$StorageAccountName.$StorageAccountDomain"
    }
    $BlobUriBld = New-Object System.UriBuilder($BlobFQDN)
    $BlobUriBld.Query = "restype=service&comp=properties"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='GET';
    }
    $BlobHeaders = @{
        "x-ms-date" = $AccessDate.ToString('R');
        "x-ms-version" = $ApiVersion;
    }
    $SasToken = New-SASToken -Verb GET -Resource $BlobUriBld.Uri -AccessKey $AccessKey -Headers $BlobHeaders
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $BlobResult=InvokeAzureStorageRequest @RequestParams|Select-Object -ExpandProperty StorageServiceProperties
    Write-Output $BlobResult
}

Function Get-AzureBlobContainerProperties
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
    $AccessDate = [DateTime]::UtcNow
    $BlobFQDN="https://$StorageAccountName.$StorageAccountDomain"
    #Build the uri..
    if($UseHttp.IsPresent)
    {
        $BlobFQDN="http://$StorageAccountName.$StorageAccountDomain"
    }
    $BlobUriBld=New-Object System.UriBuilder($BlobFQDN)
    $BlobUriBld.Path="$ContainerName"
    $BlobUriBld.Query="restype=container"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='GET';
        ReturnHeaders=$true;
    }
    $BlobHeaders= @{
        "x-ms-date"=$AccessDate.ToString('R');
        "x-ms-version"=$ApiVersion;
    }
    $SasToken=New-SASToken -Verb GET -Resource $BlobUriBld.Uri -AccessKey $AccessKey -Headers $BlobHeaders
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result=InvokeAzureStorageRequest @RequestParams
    Write-Output $Result
}

Function Get-AzureBlobContainerAcl
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$ContainerName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "blob.core.windows.net",
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )
    $AccessDate = [DateTime]::UtcNow
    $BlobFQDN = "https://$StorageAccountName.$StorageAccountDomain"
    #Build the uri..
    if ($UseHttp.IsPresent)
    {
        $BlobFQDN = "http://$StorageAccountName.$StorageAccountDomain"
    }
    $BlobUriBld = New-Object System.UriBuilder($BlobFQDN)
    $BlobUriBld.Path = "$ContainerName"
    $BlobUriBld.Query = "restype=container&comp=acl"
    $RequestParams=@{
            Uri=$BlobUriBld.Uri;
            Method='GET';
            ReturnHeaders=$true;
    }
    $BlobHeaders = @{
        "x-ms-date" = $AccessDate.ToString('R');
        "x-ms-version" = $ApiVersion;
    }
    $SasToken = New-SASToken -Verb GET -Resource $BlobUriBld.Uri -AccessKey $AccessKey -Headers $BlobHeaders
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result = InvokeAzureStorageRequest @RequestParams
    Write-Output $Result.'x-ms-blob-public-access'
}

Function Set-AzureBlobContainerAcl
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$ContainerName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "blob.core.windows.net",
        [ValidateSet('container','blob','private')]
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessLevel,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )
    $AccessDate = [DateTime]::UtcNow
    $BlobFQDN = "https://$StorageAccountName.$StorageAccountDomain"
    #Build the uri..
    if ($UseHttp.IsPresent)
    {
        $BlobFQDN = "http://$StorageAccountName.$StorageAccountDomain"
    }
    $BlobUriBld = New-Object System.UriBuilder($BlobFQDN)
    $BlobUriBld.Path = "$ContainerName"
    $BlobUriBld.Query = "restype=container&comp=acl"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='PUT';
        ReturnHeaders=$true;
    }
    $BlobHeaders = @{
        "x-ms-date" = $AccessDate.ToString('R');
        "x-ms-version" = $ApiVersion;
    }
    if($AccessLevel -ne 'private')
    {
        $BlobHeaders.Add('x-ms-blob-public-access',$AccessLevel)
    }
    $SasToken = New-SASToken -Verb PUT -Resource $BlobUriBld.Uri -AccessKey $AccessKey -Headers $BlobHeaders
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result = InvokeAzureStorageRequest @RequestParams
    $Acl=$Result.'x-ms-blob-public-access'
    if([String]::IsNullOrEmpty($Acl))
    {
        $Acl='private'
    }
    Write-Output $Acl
}

Function New-AzureBlobContainer
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$ContainerName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "blob.core.windows.net",
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )
    $BlobFQDN = "https://$StorageAccountName.$StorageAccountDomain"
    #Build the uri..
    if ($UseHttp.IsPresent)
    {
        $BlobFQDN = "http://$StorageAccountName.$StorageAccountDomain"
    }
    $BlobUriBld = New-Object System.UriBuilder($BlobFQDN)
    $BlobUriBld.Path = $ContainerName.ToLower()
    $BlobUriBld.Query = "restype=container"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='PUT';
        ReturnHeaders=$true;
    }
    $BlobHeaders = @{
        "x-ms-date" = [DateTime]::UtcNow.ToString('R');
        "x-ms-version" = $ApiVersion;
    }
    $SasToken = New-SASToken -Verb PUT -Resource $BlobUriBld.Uri -AccessKey $AccessKey -Headers $BlobHeaders
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result = InvokeAzureStorageRequest @RequestParams
    Write-Output $Result
}

Function Remove-AzureBlobContainer
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$ContainerName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "blob.core.windows.net",
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )
    $AccessDate = [DateTime]::UtcNow
    $BlobFQDN = "https://$StorageAccountName.$StorageAccountDomain"
    #Build the uri..
    if ($UseHttp.IsPresent)
    {
        $BlobFQDN = "http://$StorageAccountName.$StorageAccountDomain"
    }
    $BlobUriBld = New-Object System.UriBuilder($BlobFQDN)
    $BlobUriBld.Path = "$ContainerName"
    $BlobUriBld.Query = "restype=container"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='DELETE';
        ReturnHeaders=$true;
    }
    $BlobHeaders = @{
        "x-ms-date" = $AccessDate.ToString('R');
        "x-ms-version" = $ApiVersion;
    }
    $SasToken = New-SASToken -Verb DELETE -Resource $BlobUriBld.Uri -AccessKey $AccessKey -Headers $BlobHeaders
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result = InvokeAzureStorageRequest @RequestParams
    Write-Output $Result
}

Function Set-AzureBlobContainerLease
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$ContainerName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "blob.core.windows.net",
        [ValidateSet('Acquire','Renew','Change','Release','Break')]
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$LeaseAction,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [Guid]$Id,
        [ValidateRange(-1,60)]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$Duration=-1,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )
    $AccessDate = [DateTime]::UtcNow
    $BlobFQDN = "https://$StorageAccountName.$StorageAccountDomain"
    #Build the uri..
    if ($UseHttp.IsPresent)
    {
        $BlobFQDN = "http://$StorageAccountName.$StorageAccountDomain"
    }
    $BlobUriBld = New-Object System.UriBuilder($BlobFQDN)
    $BlobUriBld.Path = "$ContainerName"
    $BlobUriBld.Query = "comp=lease&restype=container"

    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='PUT';
        ReturnHeaders=$true;
    }

    $BlobHeaders = @{
        "x-ms-date" = $AccessDate.ToString('R');
        "x-ms-version" = $ApiVersion;
    }
    if($LeaseAction -in 'Renew','Change','Release')
    {
        if($Id -eq [guid]::Empty)
        {
            throw "A Lease Id must be specified for 'Renew','Change','Release' action"
        }
        $BlobHeaders.Add('x-ms-lease-id',$Id)
        if($LeaseAction -eq 'Change')
        {
            $BlobHeaders.Add('x-ms-proposed-lease-id',[Guid]::NewGuid())
        }
    }
    elseif($LeaseAction -eq 'Break')
    {
        if($Duration -ne -1)
        {
            $BlobHeaders.Add('x-ms-lease-break-period',$Duration)
        }
    }
    elseif($LeaseAction -eq 'Acquire')
    {
        $BlobHeaders.Add('x-ms-lease-duration',$Duration)
    }
    $BlobHeaders.Add('x-ms-lease-action',$LeaseAction.ToLower())
    $SasToken = New-SASToken -Verb PUT -Resource $BlobUriBld.Uri -AccessKey $AccessKey -Headers $BlobHeaders
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result = InvokeAzureStorageRequest @RequestParams
    Write-Output $Result
}

Function Get-AzureBlobMetadata
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Uri[]]$InputObject,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$StorageAccountName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ContainerName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$BlobName,        
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$StorageAccountDomain="blob.core.windows.net",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$AccessKey,
        [Parameter(Mandatory=$false,ParameterSetName='indirect')]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ApiVersion="2016-05-31"
    )
    PROCESS
    {
        if($PSCmdlet.ParameterSetName -eq 'indirect')
        {
            $Scheme='https'
            if($UseHttp.IsPresent)
            {
                $Scheme='http'
            }
            $InputObject=@(New-Object Uri("$($Scheme)://$($StorageAccountName).$($StorageAccountDomain)/$($ContainerName/$BlobName)"))
        }
        foreach($item in $InputObject)
        {
            if([String]::IsNullOrEmpty($StorageAccountName))
            {
                $StorageAccountName=$item.Host.Split('.')|Select-Object -First 1
            }
            $BlobUriBld=New-Object System.UriBuilder($item)
            $BlobUriBld.Query="comp=metadata"
            $RequestParams=@{
                Uri=$BlobUriBld.Uri;
                Method='GET';
                ReturnHeaders=$true;
            }
            $BlobHeaders= @{
                "x-ms-date"=[DateTime]::UtcNow.ToString('R');
                "x-ms-version"=$ApiVersion;
            }
            $SasToken=New-SASToken -Verb GET -Resource $BlobUriBld.Uri -Headers $BlobHeaders
            $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
            $RequestParams.Add('Headers',$BlobHeaders)
            $Result=InvokeAzureStorageRequest @RequestParams
            Write-Output $Result
        }
    }
}

Function Get-AzureBlobProperties
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Uri[]]$InputObject,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$StorageAccountName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ContainerName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$BlobName,        
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$StorageAccountDomain="blob.core.windows.net",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$AccessKey,
        [Parameter(Mandatory=$false,ParameterSetName='indirect')]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ApiVersion="2016-05-31"
    )
    PROCESS
    {
        if($PSCmdlet.ParameterSetName -eq 'indirect')
        {
            $InputObject=@(New-Object Uri("https://$StorageAccountName.$StorageAccountDomain/$ContainerName/$BlobName"))
        }
        foreach($item in $InputObject)
        {
            if([String]::IsNullOrEmpty($StorageAccountName))
            {
                $StorageAccountName=$item.Host.Split('.')|Select-Object -First 1
            }
            $BlobUriBld=New-Object System.UriBuilder($item)
            $RequestParams=@{
                Uri=$BlobUriBld.Uri;
                Method='GET';
                ReturnHeaders=$true;
            }
            $BlobHeaders= @{
                "x-ms-date"=[DateTime]::UtcNow.ToString('R');
                "x-ms-version"=$ApiVersion;
            }
            $SasToken=New-SASToken -Verb GET -Resource $BlobUriBld.Uri -Headers $BlobHeaders
            $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
            $RequestParams.Add('Headers',$BlobHeaders)
            $Result=InvokeAzureStorageRequest @RequestParams
            Write-Output $Result
        }
    }
}

Function Set-AzureBlobMetadata
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Uri[]]$InputObject,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$StorageAccountName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ContainerName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$BlobName,        
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$StorageAccountDomain="blob.core.windows.net",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$AccessKey,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true,ParameterSetName='direct')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true,ParameterSetName='indirect')]
        [System.Collections.IDictionary]$Metadata,
        [Parameter(Mandatory=$false,ParameterSetName='indirect')]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ApiVersion="2016-05-31"
    )

    PROCESS
    {
        if($PSCmdlet.ParameterSetName -eq 'indirect')
        {
            $Scheme='https'
            if($UseHttp.IsPresent)
            {
                $Scheme='http'
            }
            $InputObject=@(New-Object Uri("$($Scheme)://$($StorageAccountName).$($StorageAccountDomain)/$($ContainerName/$BlobName)"))
        }
        foreach($item in $InputObject)
        {
            if([String]::IsNullOrEmpty($StorageAccountName))
            {
                $StorageAccountName=$item.Host.Split('.')|Select-Object -First 1
            }
            $BlobUriBld=New-Object System.UriBuilder($item)
            $RequestParams=@{
                Uri=$BlobUriBld.Uri;
                Method='GET';
                ReturnHeaders=$true;
            }
            $BlobHeaders= @{
                "x-ms-date"=[DateTime]::UtcNow.ToString('R');
            }
            foreach($MetaKey in ($Metadata.Keys|Sort-Object))
            {
                $BlobHeaders.Add("x-ms-meta-$MetaKey",$Metadata[$MetaKey])
            }
            $BlobHeaders.Add("x-ms-version",$ApiVersion)            
            $SasToken=New-SASToken -Verb GET -Resource $BlobUriBld.Uri -Headers $BlobHeaders
            $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
            $RequestParams.Add('Headers',$BlobHeaders)
            $Result=InvokeAzureStorageRequest @RequestParams
            Write-Output $Result
        }
    }
}

Function New-AzureBlobSnapshot
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Uri[]]$InputObject,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$StorageAccountName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ContainerName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$BlobName,        
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$StorageAccountDomain="blob.core.windows.net",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$AccessKey,
        [Parameter(Mandatory=$false,ParameterSetName='indirect')]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ApiVersion="2016-05-31"
    )
    PROCESS
    {
        if($PSCmdlet.ParameterSetName -eq 'indirect')
        {
            $Scheme='https'
            if($UseHttp.IsPresent)
            {
                $Scheme='http'
            }
            $InputObject=@(New-Object Uri("$($Scheme)://$($StorageAccountName).$($StorageAccountDomain)/$($ContainerName/$BlobName)"))
        }
        foreach($item in $InputObject)
        {
            if([String]::IsNullOrEmpty($StorageAccountName))
            {
                $StorageAccountName=$item.Host.Split('.')|Select-Object -First 1
            }
            $BlobUriBld=New-Object System.UriBuilder($item)
            $BlobUriBld.Query="comp=snapshot"
            $RequestParams=@{
                Uri=$BlobUriBld.Uri;
                Method='PUT';
                ReturnHeaders=$true;
            }
            $BlobHeaders= @{
                "x-ms-date"=[DateTime]::UtcNow.ToString('R');
                "x-ms-version"=$ApiVersion;
            }
            $SasToken=New-SASToken -Verb PUT -Resource $BlobUriBld.Uri -Headers $BlobHeaders
            $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
            $RequestParams.Add('Headers',$BlobHeaders)
            $Result=InvokeAzureStorageRequest @RequestParams
        }
    }
}

Function Remove-AzureBlob
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Uri[]]$InputObject,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$StorageAccountName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ContainerName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$BlobName,        
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$StorageAccountDomain="blob.core.windows.net",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$AccessKey,
        [Parameter(Mandatory=$false,ParameterSetName='indirect')]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ParameterSetName='direct')]
        [Parameter(Mandatory=$false,ParameterSetName='indirect')]
        [Guid]$LeaseId,
        [Parameter(Mandatory=$false,ParameterSetName='indirect')]
        [Parameter(Mandatory=$false,ParameterSetName='direct')]
        [Switch]$DeleteSnapshots,
        [Parameter(Mandatory=$false,ParameterSetName='indirect')]
        [Parameter(Mandatory=$false,ParameterSetName='direct')]
        [Switch]$OnlySnapshots,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ApiVersion="2016-05-31"
    )
    PROCESS
    {
        if($PSCmdlet.ParameterSetName -eq 'indirect')
        {
            $Scheme='https'
            if($UseHttp.IsPresent)
            {
                $Scheme='http'
            }
            $InputObject=@(New-Object Uri("$($Scheme)://$($StorageAccountName).$($StorageAccountDomain)/$($ContainerName/$BlobName)"))
        }
        foreach($item in $InputObject)
        {
            if([String]::IsNullOrEmpty($StorageAccountName))
            {
                $StorageAccountName=$item.Host.Split('.')|Select-Object -First 1
            }
            $BlobUriBld=New-Object System.UriBuilder($item)
            $RequestParams=@{
                Uri=$BlobUriBld.Uri;
                Method='DELETE';
                ReturnHeaders=$true;
            }
            $BlobHeaders= @{
                "x-ms-date"=[DateTime]::UtcNow.ToString('R');
                "x-ms-version"=$ApiVersion;
            }
            if($LeaseId -ne [Guid]::Empty)
            {
                $BlobHeaders.Add('x-ms-lease-id',$LeaseId)
            }
            if($DeleteSnapshots.IsPresent)
            {
                $BlobHeaders.Add('x-ms-delete-snapshots','include')
            }
            elseif($OnlySnapshots.IsPresent)
            {
                $BlobHeaders.Add('x-ms-delete-snapshots','only')
            }
            $SasToken=New-SASToken -Verb DELETE -Resource $BlobUriBld.Uri -Headers $BlobHeaders
            $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
            $RequestParams.Add('Headers',$BlobHeaders)
            $Result=InvokeAzureStorageRequest @RequestParams
            Write-Output $Result
        }
    }
}