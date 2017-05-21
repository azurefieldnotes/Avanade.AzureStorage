
#region Constants
$Script:UTF8ByteOrderMark=[System.Text.Encoding]::Default.GetString([System.Text.Encoding]::UTF8.GetPreamble())

#Permissions - QUERY: 'r',ADD: 'a',UPDATE: 'u',DELETE: 'd'
$Script:TableAclTemplate=@"
<SignedIdentifier>   
<Id>{0}</Id>  
<AccessPolicy>  
    <Start>{2}</Start>  
    <Expiry>{3}</Expiry>  
    <Permission>{1}</Permission>  
</AccessPolicy>  
</SignedIdentifier>
"@
$Script:TableAclRequestTemplate=@"
<?xml version="1.0" encoding="utf-8"?>  
<SignedIdentifiers>  
  {0}
</SignedIdentifiers>
"@
#endregion

#region Helpers

Function EncodeStorageRequest
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String[]]$StringToSign,        
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$SigningKey
    )
    PROCESS
    {
        foreach ($item in $StringToSign)
        {
            $KeyBytes = [System.Convert]::FromBase64String($SigningKey)
            $HMAC = New-Object System.Security.Cryptography.HMACSHA256
            $HMAC.Key = $KeyBytes
            $UnsignedBytes = [System.Text.Encoding]::UTF8.GetBytes($item)
            $KeyHash = $HMAC.ComputeHash($UnsignedBytes)
            $SignedString=[System.Convert]::ToBase64String($KeyHash)
            Write-Output $SignedString                    
        }
    }
}

Function GetTokenStringToSign
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('GET','PUT','DELETE','POST','OPTIONS')]
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
        $Date,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $ContentLanguage,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $ContentEncoding,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $IfModifiedSince,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $IfUnmodifiedSince, 
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $IfMatch,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $IfNoneMatch,                
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $ContentType,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $ContentMD5,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [long]
        $RangeStart,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [long]
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
            $Range="bytes=$($RangeStart)-$($RangeEnd-1)"
        }

        $SigningPieces=@(
            $Verb,$ContentEncoding,
            $ContentLanguage,$LengthString,
            $ContentMD5,$ContentType,$Date,$IfModifiedSince,$IfMatch,$IfNoneMatch,$IfUnmodifiedSince,$Range
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

Function GetTableTokenStringToSign
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('GET','PUT','DELETE','POST','OPTIONS')]
        [string]
        $Verb="GET",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]
        $Resource,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $ContentMD5,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $ContentType,
        [String]
        $Date
    )

    $ResourceBase=($Resource.Host.Split('.') | Select-Object -First 1).TrimEnd("`0")
    $ResourcePath=$Resource.LocalPath.TrimStart('/').TrimEnd("`0")
    $SigningPieces=@($Verb,$ContentMD5,$ContentType,$Date)
    #Get the canonicalized resource...
    $CanonicalizedResource="/$ResourceBase/$ResourcePath"
    if([String]::IsNullOrEmpty($Resource.Query) -eq $false)
    {
        foreach ($item in $Resource.Query.TrimStart('?').ToLower().Split('&')) {
            if($item.StartsWith('comp='))
            {
                $CanonicalizedResource+="?$item"
                break
            }
        }
    }
    $SigningPieces+=$CanonicalizedResource
    $StringToSign = [String]::Join("`n",$SigningPieces)
    Write-Output $StringToSign 
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
        [System.Collections.IDictionary]
        $Headers,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]
        $ReturnHeaders,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [String]
        $ContentType,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [String]
        $ExpandProperty
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
        if([string]::IsNullOrEmpty($ContentType) -eq $false)
        {
            $RequestParams.Add('ContentType',$ContentType)
        }
        $Response=Invoke-WebRequest @RequestParams
        if($Response -ne $null)
        {
            if($ReturnHeaders.IsPresent -and $Response.Headers -ne $null)
            {
                Write-Output $Response.Headers
            }
            $ResponseType="application/xml"
            if($Response.Headers -ne $null -and (-not [String]::IsNullOrEmpty($Response.Headers['Content-Type'])))
            {
                $ResponseType=$Response.Headers['Content-Type']
            }
            if ([String]::IsNullOrEmpty($Response.Content) -eq $false)
            {
                $ResultString=$Response.Content
                if($ResultString.StartsWith($Script:UTF8ByteOrderMark,[System.StringComparison]::Ordinal))
                {
                    #Really UTF-8 BOM???
                    $ResultString=$ResultString.Remove(0,$Script:UTF8ByteOrderMark.Length)
                }
                if(-not [String]::IsNullOrEmpty($ExpandProperty))
                {
                    if($ResponseType -like 'application*xml*')
                    {
                        $Result=$(([Xml]$ResultString)|Select-Object -ExpandProperty $ExpandProperty)
                    }
                    elseif($ResponseType -like 'application/json*')
                    {
                        $Result=$(($ResultString|ConvertFrom-Json)|Select-Object -ExpandProperty $ExpandProperty)
                    }
                    Write-Output $Result
                }
                else
                {
                    if($ResponseType -like 'application*xml*')
                    {
                        [Xml]$Result=$ResultString
                    }
                    elseif($ResponseType -like 'application/json*')
                    {
                        $Result=$ResultString|ConvertFrom-Json
                    }                    
                    Write-Output $Result
                }
            }
        }
    }
}

Function GetStorageUri
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$AccountName,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$StorageServiceFQDN,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$IsInsecure
    )
    if($IsInsecure)
    {
        $Scheme='http'
    }
    else
    {
        $Scheme='https'
    }
    $ResultUri=New-Object System.Uri("$($Scheme)://$AccountName.$StorageServiceFQDN")
    Write-Output $ResultUri
}

<#
    .SYNOPSIS
        Retreives a large file over HTTP
#>
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
        $BufferSize =  4096000
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
        Write-Progress -Activity $Activity -Status "Status:$($WebResponse.StatusCode) $ContentType Response of $($TotalSize/1MB) MB" -PercentComplete 0
        Write-Verbose "$Activity - Status:$($WebResponse.StatusCode) $ContentType Response of $($TotalSize/1MB) MB"
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
            $Speed=[Math]::Round(($BytesWritten/1MB)/$Stopwatch.Elapsed.TotalSeconds,2)
            #Write-Verbose "$Activity - Writing Response $ContentType $(Split-Path -Path $Destination -Leaf) - $BytesWritten"
            Write-Progress -Activity $Activity -Status "Response $ContentType $(Split-Path -Path $Destination -Leaf) $([Math]::Round($BytesWritten/1MB)) MB written - ($Speed mb/s)" `
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

<#
    .SYNOPSIS
        Retreives an MD5 hash for either a file or arbitrary bytes
#>
Function GetMd5Hash
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ParameterSetName='file')]
        [System.IO.FileInfo[]]$InputObject,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ParameterSetName='content')]
        [System.Byte[]]$Content        
    )
    BEGIN
    {
        $Hasher= New-Object System.Security.Cryptography.MD5CryptoServiceProvider
    }
    PROCESS
    {
        if($PSCmdlet.ParameterSetName -eq 'file')
        {
            foreach ($item in $InputObject)
            {
                Write-Verbose "[GetMd5Hash] Calculating MD5 Hash for $($item.FullName)"
                $Md5Hash=@()
                $HashResult=Get-FileHash -Path $item.FullName -Algorithm MD5|Select-Object -ExpandProperty Hash
                for ($i = 0; $i -lt $HashResult.Length; $i+=2)
                { 
                    $Md5Hash+=$([Byte]::Parse($HashResult.Substring($i,2) -f "0:x",[System.Globalization.NumberStyles]::HexNumber))
                }
                Write-Output $([System.Convert]::ToBase64String($Md5Hash))
            }
        }
        else
        {
            Write-Verbose "[GetMd5Hash] Calculating MD5 Hash for Bytes Length $($Content.Length)"
            $Md5Hash=$Hasher.ComputeHash($Content)
            Write-Output $([System.Convert]::ToBase64String($Md5Hash))
        }
    }
    END
    {
        $Hasher.Dispose()
    }
}

#endregion

<#
    .SYNOPSIS
        Generates a new Shared Key Signature
    .PARAMETER Verb
        The HTTP Verb for the request
    .PARAMETER Resource
        The resource to be accessed
    .PARAMETER ContentLength
        The Content-Length header value
    .PARAMETER ContentEncoding
        The Content-Encoding header value
    .PARAMETER ContentType
        The Content-Type header value  
    .PARAMETER ContentMD5
        The Content-MD5 header value
    .PARAMETER RangeStart
        The Range header start value 
    .PARAMETER RangeEnd
        The Range header end value
    .PARAMETER Headers
        The Request Header collection (usually 'including the canonical x-ms-date and x-ms-version')
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER ServiceType
        The storage service type to be accessed

#>
Function New-SharedKeySignature
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('GET','PUT','DELETE','POST','OPTIONS')]
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $IfModifiedSince,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $IfUnmodifiedSince, 
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $IfMatch,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]
        $IfNoneMatch,          
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [String]
        $ContentType,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [String]
        $Date,
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [System.Collections.IDictionary]
        $Headers,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Blob','Table','Queue','File')]
        [String]
        $ServiceType='BLOB'
    )
    BEGIN
    {
        Write-Verbose "[New-SharedKeySignature] Encoding Signature for service:$ServiceType - $Resource"
        $CopiedHeaders=[ordered]@{}
        foreach ($HeaderName in $Headers.Keys)
        {
            if($HeaderName -eq 'Date')
            {
                if([String]::IsNullOrEmpty($Date))
                {
                    $Date=$Headers['Date']
                }
            }
            elseif($HeaderName -eq 'x-ms-date')
            {
                if([String]::IsNullOrEmpty($Date))
                {
                    $Date=$Headers['x-ms-date']
                    $CopiedHeaders.Add($HeaderName,$Headers[$HeaderName])
                }                
            }            
            elseif($HeaderName -eq 'Content-MD5')
            {
                if([String]::IsNullOrEmpty($ContentMD5))
                {
                    $ContentMD5=$Headers['Content-MD5']
                }                
            }
            elseif($HeaderName -eq 'Content-Type')
            {
                if([String]::IsNullOrEmpty($ContentType))
                {
                    $ContentType=$Headers['Content-Type']
                }                
            }
            elseif($HeaderName -eq 'Content-Encoding')
            {
                if([String]::IsNullOrEmpty($ContentType))
                {
                    $ContentEncoding=$Headers['Content-Encoding']
                }                
            }
            else
            {
                $CopiedHeaders.Add($HeaderName,$Headers[$HeaderName])
            }
        }
        $SigningElements=@{
            Verb=$Verb;
            Resource=$Resource;
            ContentMD5=$ContentMD5;
            ContentType=$ContentType;
        }
        if($ServiceType -ne'Table')
        {           
            $SigningElements.Add('ContentLanguage',$ContentLanguage)
            $SigningElements.Add('ContentEncoding',$ContentEncoding)
            $SigningElements.Add('RangeStart',$RangeStart)
            $SigningElements.Add('RangeEnd',$RangeEnd)
            $SigningElements.Add('ContentLength',$ContentLength)
            $SigningElements.Add('Headers',$CopiedHeaders)
        }
        else
        {
            $SigningElements.Add('Date',$Date)
        }
    }
    PROCESS
    {
        if($ServiceType -eq 'Table')
        {
            $StringToSign = GetTableTokenStringToSign @SigningElements
        }
        else
        {
            $StringToSign = GetTokenStringToSign @SigningElements            
        }
        Write-Verbose "[New-SharedKeySignature] String to Sign:$StringToSign"
        $SharedAccessSignature=EncodeStorageRequest -StringToSign $StringToSign -SigningKey $AccessKey
        Write-Output $SharedAccessSignature        
    }
}

#region Table

<#
    .SYNOPSIS
        Returns properties for the table service on the storage account
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the storage service API        
#>
Function Get-AzureTableServiceProperties
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$StorageAccountDomain="table.core.windows.net",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$AccessKey,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ApiVersion="2016-05-31",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ODataServiceVersion='3.0;Netfx'
    )
    
    BEGIN
    {
        $TableHeaders=[ordered]@{
            'x-ms-version'=$ApiVersion
            'DataServiceVersion'=$ODataServiceVersion
            'Accept-Charset'='UTF-8'
            'Date'=[DateTime]::UtcNow.ToString('R');
        }
        $TableUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
        $TableUriBld=New-Object System.UriBuilder($TableUri)
        $TableUriBld.Path='/'
        $TableUriBld.Query="restype=service&comp=properties"
        $TokenParams=@{
            Resource=$TableUriBld.Uri;
            Verb='GET';
            Headers=$TableHeaders;
            ServiceType='Table';
            AccessKey=$AccessKey;
        }
        $RequestParams=@{
            Uri=$TableUriBld.Uri;
            Method='GET';
            Headers=$TableHeaders;
            ExpandProperty="StorageServiceProperties";
        }
    }
    PROCESS
    {
        $TableSignature=New-SharedKeySignature @TokenParams
        $RequestParams.Headers.Add('Authorization',"SharedKey $($StorageAccountName):$($TableSignature)")
        $TableResult=InvokeAzureStorageRequest @RequestParams
        Write-Output $TableResult
    }
}

<#
    .SYNOPSIS
        Retrieves the list of tables within the storage account
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the storage service API        
#>
Function Get-AzureTableServiceTables
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$StorageAccountDomain="table.core.windows.net",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$AccessKey,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ApiVersion="2016-05-31",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ODataServiceVersion='3.0;Netfx',
        [ValidateSet('application/json;odata=nometadata','application/json;odata=minimalmetadata','application/json;odata=fullmetadata')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ContentType='application/json;odata=nometadata'
    )
    BEGIN
    {
        $TableHeaders=[ordered]@{
            'x-ms-version'=$ApiVersion
            'DataServiceVersion'=$ODataServiceVersion
            'Accept-Charset'='UTF-8'
            'Accept'=$ContentType;
            'Date'=[DateTime]::UtcNow.ToString('R');
        }
        $TableUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
        $TableUriBld=New-Object System.UriBuilder($TableUri)
        $TableUriBld.Path='tables'
        $TokenParams=@{
            Resource=$TableUriBld.Uri;
            Verb='GET';
            Headers=$TableHeaders;
            ContentType=$ContentType;
            ServiceType='Table';
            AccessKey=$AccessKey;
        }
        $RequestParams=@{
            Uri=$TableUriBld.Uri;
            Method='GET';
            Headers=$TableHeaders;
            ExpandProperty='value';
            ContentType=$ContentType;
        }
    }
    PROCESS
    {
        $TableSignature=New-SharedKeySignature @TokenParams
        $RequestParams.Headers.Add('Authorization',"SharedKey $($StorageAccountName):$($TableSignature)")
        $Response=InvokeAzureStorageRequest @RequestParams
        Write-Output $Response
    }
}

<#
    .SYNOPSIS
        Returns statistics for the table service on the storage account
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the storage service API        
#>
Function Get-AzureTableServiceStats
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "table.core.windows.net",
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ODataServiceVersion='3.0;Netfx'        
    )
    $TableUri=GetStorageUri -AccountName "$StorageAccountName" -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $TableUriBld=New-Object System.UriBuilder($TableUri)
    $TableUriBld.Query = "restype=service&comp=stats"

    $TableHeaders=[ordered]@{
        'x-ms-version'=$ApiVersion
        'DataServiceVersion'=$ODataServiceVersion
        'Accept-Charset'='UTF-8'
        'Date'=[DateTime]::UtcNow.ToString('R');
    }   
    $TokenParams=@{
        Resource=$TableUriBld.Uri;
        Verb='GET';
        Headers=$TableHeaders;
        ServiceType='Table';
        AccessKey=$AccessKey;
    }
    $TableSignature=New-SharedKeySignature @TokenParams
    $TableHeaders.Add('Authorization',"SharedKey $($StorageAccountName):$($TableSignature)")
    $TableUriBld.Host="$StorageAccountName-secondary.$StorageAccountDomain"
    $RequestParams=@{
        Uri=$TableUriBld.Uri;
        Method='GET';
        Headers=$TableHeaders;
        ExpandProperty='StorageServiceStats'
    }
    $TableStats=InvokeAzureStorageRequest @RequestParams
    Write-Output $TableStats
}

<#
    .SYNOPSIS
        Returns ACL(s) for the table
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER TableName
        The name of the table
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the storage service API        
#>
Function Get-AzureTableACL
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$TableName,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "table.core.windows.net",
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ODataServiceVersion='3.0;Netfx'        
    )
    $TableUri=GetStorageUri -AccountName "$StorageAccountName" -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $TableUriBld=New-Object System.UriBuilder($TableUri)
    $TableUriBld.Path=$TableName
    $TableUriBld.Query = "comp=acl"

    $TableHeaders=[ordered]@{
        'x-ms-version'=$ApiVersion
        'DataServiceVersion'=$ODataServiceVersion
        'Accept-Charset'='UTF-8'
        'Date'=[DateTime]::UtcNow.ToString('R');
    }   
    $TokenParams=@{
        Resource=$TableUriBld.Uri;
        Verb='GET';
        Headers=$TableHeaders;
        ServiceType='Table';
        AccessKey=$AccessKey;
    }
    $TableSignature=New-SharedKeySignature @TokenParams
    $TableHeaders.Add('Authorization',"SharedKey $($StorageAccountName):$TableSignature")
    $RequestParams=@{
        Uri=$TableUriBld.Uri;
        Method='GET';
        Headers=$TableHeaders;
        ExpandProperty="SignedIdentifiers";
    }
    $TableACls=InvokeAzureStorageRequest @RequestParams
    if($TableACls -ne $null -and  $TableACls.SignedIdentifier -ne $null)
    {
        foreach ($item in $TableACls.SignedIdentifier)
        {
            Write-Output $item
        }
    }
}

<#
    .SYNOPSIS
        Sets an ACL on the table
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER TableName
        The name of the table
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the storage service API        
#>
Function Set-AzureTableACL
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$TableName,
        [Parameter(ValueFromPipeline=$true,Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [ValidateLength(1,4)]
        [ValidateSet('r','a','u','d','ra','ru','rud','rd','rau','rad','raud','au','aud','ad','ud')]
        [String]$Acl,
        [Parameter(ValueFromPipeline=$true,Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.DateTime]$Start=[DateTime]::UtcNow,
        [Parameter(ValueFromPipeline=$true,Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.DateTime]$Expiry=($Start.AddDays(365)),
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "table.core.windows.net",
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ODataServiceVersion='3.0;Netfx'        
    )

    $TableUri=GetStorageUri -AccountName "$StorageAccountName" -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $TableUriBld=New-Object System.UriBuilder($TableUri)
    $TableUriBld.Path=$TableName
    $TableUriBld.Query = "comp=acl"

    $TableHeaders=[ordered]@{
        'x-ms-version'=$ApiVersion
        'DataServiceVersion'=$ODataServiceVersion
        'Accept-Charset'='UTF-8'
        'Date'=[DateTime]::UtcNow.ToString('R');
    }
    $TokenParams=@{
        Resource=$TableUriBld.Uri;
        Verb='PUT';
        Headers=$TableHeaders;
        ServiceType='Table';
        AccessKey=$AccessKey;
        ContentType='application/xml'
    }
    $TableSignature=New-SharedKeySignature @TokenParams
    $TableHeaders.Add('Authorization',"SharedKey $($StorageAccountName):$TableSignature")
    $AclId=[Convert]::ToBase64String(([Guid]::NewGuid()).ToByteArray())
    $StartTime=$Start.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fffffffK")
    $EndTime=$Expiry.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fffffffK")
    $AclBody=$Script:TableAclRequestTemplate -f  $($Script:TableAclTemplate -f $AclId,$Acl,$StartTime,$EndTime)
    Write-Verbose "[Set-AzureTableACL] Creating ACL $AclId for $TableUri $AclBody"
    $RequestParams=@{
        Uri=$TableUriBld.Uri;
        Method='PUT';
        Headers=$TableHeaders;
        ReturnHeaders=$true;
        Body=$AclBody;
        ContentType='application/xml'
    }
    $TableACls=InvokeAzureStorageRequest @RequestParams
    Write-Verbose "[Set-AzureTableACL] Created $AclId successfully."
    Write-Output $TableACls
}

<#
    .SYNOPSIS
        Creates a new table on the storage account
#>
Function New-AzureTable
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$TableName,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "table.core.windows.net",
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ODataServiceVersion='3.0;Netfx',
        [ValidateSet('application/json;odata=nometadata','application/json;odata=minimalmetadata','application/json;odata=fullmetadata')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ContentType='application/json;odata=nometadata',        
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$ReturnDetail
    )

    $TableUri=GetStorageUri -AccountName "$StorageAccountName" -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $TableUriBld=New-Object System.UriBuilder($TableUri)
    $TableUriBld.Path='Tables'
    $ReturnContentPref="return-no-content"
    if($ReturnDetail.IsPresent)
    {
        $ReturnContentPref='return-content'
    }
    $TableHeaders=[ordered]@{
        'x-ms-version'=$ApiVersion
        'DataServiceVersion'=$ODataServiceVersion
        'Accept-Charset'='UTF-8'
        'Accept'=$ContentType
        'Date'=[DateTime]::UtcNow.ToString('R');
        'Prefer'=$ReturnContentPref;
    }
    
    $TokenParams=@{
        Resource=$TableUriBld.Uri;
        Verb='POST';
        Headers=$TableHeaders;
        ServiceType='Table';
        AccessKey=$AccessKey;
        ContentType='application/json'
    }
    $TableSignature=New-SharedKeySignature @TokenParams
    $TableHeaders.Add('Authorization',"SharedKey $($StorageAccountName):$TableSignature")

    $NewTableBody=New-Object psobject @{
        'TableName'=$TableName;
    }

    $RequestParams=@{
        Uri=$TableUriBld.Uri;
        Method='POST';
        Headers=$TableHeaders;
        ContentType='application/json';
        Body=$($NewTableBody|ConvertTo-Json);
    }
    $NewTableResponse=InvokeAzureStorageRequest @RequestParams
    if($ReturnDetail.IsPresent)
    {
        Write-Output $NewTableResponse
    }
}

<#
    .SYNOPSIS
        Deletes the specified azure storage table
#>
Function Remove-AzureTable
{
    [CmdletBinding()]
    param
    ( 
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$TableName,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "table.core.windows.net",
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ODataServiceVersion='3.0;Netfx',
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$ReturnDetail
    )

    $TableUri=GetStorageUri -AccountName "$StorageAccountName" -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $TableUriBld=New-Object System.UriBuilder($TableUri)
    $TableUriBld.Path="Tables('$TableName')"

    $TableHeaders=[ordered]@{
        'Date'=[DateTime]::UtcNow.ToString('R');
        'x-ms-version'=$ApiVersion
        'DataServiceVersion'=$ODataServiceVersion;
        'Accept'='application/json'
    }
            
    $TokenParams=@{
        Resource=$TableUriBld.Uri;
        Verb='DELETE';
        Headers=$TableHeaders;
        ServiceType='Table';
        AccessKey=$AccessKey;
        ContentType='application/json'
    }
    $TableSignature=New-SharedKeySignature @TokenParams
    $TableHeaders.Add('Authorization',"SharedKey $($StorageAccountName):$TableSignature")
    $RequestParams=@{
        Uri=$TableUriBld.Uri;
        Method='DELETE';
        Headers=$TableHeaders;
        ContentType='application/json';
        ReturnHeaders=$true
    }
    $DeleteTableResponse=InvokeAzureStorageRequest @RequestParams
    if($ReturnDetail.IsPresent)
    {
        Write-Output $DeleteTableResponse
    }
}

<#
    .SYNOPSIS
        Queries the specified azure storage table
#>
Function Get-AzureTableEntity
{
    [CmdletBinding(DefaultParameterSetName='default')]
    param
    ( 
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='default')]
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='uniqueid')]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='default')]
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='uniqueid')]
        [String]$TableName,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='default')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='uniqueid')]
        [String]$StorageAccountDomain = "table.core.windows.net",
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='default')]
        [String]$Filter,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='default')]
        [int]$Top,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='default')]
        [int]$LimitResults,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='default')]
        [string[]]$Select,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='uniqueid')]
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='default')]
        [String]$AccessKey,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true,ParameterSetName='default')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='uniqueid')]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='uniqueid')]
        [String]$PartitionKey,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='uniqueid')]
        [String]$RowKey,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='uniqueid')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='default')]
        [String]$ApiVersion = "2016-05-31",
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='uniqueid')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='default')]
        [String]$ODataServiceVersion='3.0;Netfx',
        [ValidateSet('application/json;odata=nometadata','application/json;odata=minimalmetadata','application/json;odata=fullmetadata')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='uniqueid')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='default')]
        [String]$ContentType='application/json;odata=nometadata'
    )

    $TableUri=GetStorageUri -AccountName "$StorageAccountName" -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $TableUriBld=New-Object System.UriBuilder($TableUri)
    if(-not [string]::IsNullOrEmpty($PartitionKey))
    {
        if(-not [string]::IsNullOrEmpty($RowKey))
        {
            $TableUriBld.Path="$TableName(PartitionKey='$PartitionKey',RowKey='$RowKey')"
        }
    }
    else
    {
        $TableUriBld.Path="$TableName()"
    }
    $TableQuery=""
    $TableHeaders=[ordered]@{
        'x-ms-version'=$ApiVersion
        'DataServiceVersion'=$ODataServiceVersion
        'Accept'=$ContentType
        'Date'=[DateTime]::UtcNow.ToString('R');
    }
    if(-not [String]::IsNullOrEmpty($Filter))
    {
        $TableQuery="`$filter=$Filter"
    }
    if($PSCmdlet.ParameterSetName -eq 'default' -and $Top -gt 0)
    {
        $TableQuery+="&`$top=$Top"
    }
    if(-not [String]::IsNullOrEmpty($TableQuery))
    {
        $TableUriBld.Query = $TableQuery
    }
    $TokenParams=@{
        Resource=$TableUriBld.Uri;
        Verb='GET';
        Headers=$TableHeaders;
        ServiceType='Table';
        AccessKey=$AccessKey;
        ContentType=$ContentType;
    }
    $TotalResults=0
    $TableSignature=New-SharedKeySignature @TokenParams
    $TableHeaders.Add('Authorization',"SharedKey $($StorageAccountName):$TableSignature")
    $RequestParams=@{
        Uri=$TableUriBld.Uri;
        Method='GET';
        Headers=$TableHeaders;
        ContentType=$ContentType
    }
    $HasMore=$false
    try
    {
        $Response=Invoke-WebRequest @RequestParams
        if(-not [string]::IsNullOrEmpty($Response.Content) -and $PSCmdlet.ParameterSetName -eq 'default')
        {
            $TableResult=$(($Response.Content|ConvertFrom-Json)|Select-Object -ExpandProperty 'value')
            $TotalResults+=$TableResult.Count
            Write-Output $TableResult
            #Are there more values??
            if(-not [string]::IsNullOrEmpty($Response.Headers['x-ms-continuation-NextPartitionKey']) -and $Top -eq 0)
            {
                Write-Verbose "[Get-AzureTableEntity] More results available @ PartitionKey $($Response.Headers['x-ms-continuation-NextPartitionKey'])"
                $HasMore=$true
            }
            while ($HasMore)
            {
                $NextQueryPieces=@()
                $NextQueryPieces+="NextPartitionKey=$($Response.Headers['x-ms-continuation-NextPartitionKey'])"
                if(-not [string]::IsNullOrEmpty($Response.Headers['x-ms-continuation-NextRowKey']))
                {
                    $NextQueryPieces+="NextRowKey=$($Response.Headers['x-ms-continuation-NextRowKey'])"
                }
                if(-not [string]::IsNullOrEmpty($TableUriBld.Query))
                {
                    $TablePieces=$TableUriBld.Query.TrimStart('?').Split('&')
                    foreach ($TableQuery in $TablePieces)
                    {
                        if($TableQuery -notlike 'NextPartitionKey=*' -and $TableQuery -notlike 'NextRowKey=*')
                        {
                            $TablePieces+=$TableQuery
                        }
                    }
                }
                $TableUriBld.Query=$([string]::Join('&',$NextQueryPieces))
                $RequestParams['Uri']=$TableUriBld.Uri
                try
                {
                    $Response=Invoke-WebRequest @RequestParams
                    if(-not [string]::IsNullOrEmpty($Response.Content))
                    {   
                        $TableResult=$(($Response.Content|ConvertFrom-Json)|Select-Object -ExpandProperty 'value')
                        $TotalResults+=$TableResult.Count
                        Write-Output $TableResult
                        if(-not [string]::IsNullOrEmpty($Response.Headers['x-ms-continuation-NextPartitionKey']))
                        {
                            if($LimitResults -gt 0 -and $TotalResults -ge $LimitResults)
                            {
                                Write-Verbose "[Get-AzureTableEntity] Finished Enumerating results at limit $LimitResults"
                                $HasMore=$false
                            }
                            else
                            {
                                Write-Verbose "[Get-AzureTableEntity] Total Items:$TotalResults More results available @ Partition Key $(($Response.Headers['x-ms-continuation-NextPartitionKey']))"
                                $HasMore=$true
                            }
                        }
                        else
                        {
                            $HasMore=$false
                        }
                    }
                }
                catch
                {
                    $HasMore=$false
                    #See if we can unwind an exception from a response
                    if($_.Exception.Response -ne $null)
                    {
                        $ExceptionResponse=$_.Exception.Response
                        $ErrorStream=$ExceptionResponse.GetResponseStream()
                        $ErrorStream.Position=0
                        $StreamReader = New-Object System.IO.StreamReader($ErrorStream)
                        try
                        {
                            $ErrorContent=$StreamReader.ReadToEnd()
                            $StreamReader.Close()
                        }
                        catch
                        {
                        }
                        finally
                        {
                            $StreamReader.Close()
                        }
                        $ErrorMessage="Error: $($ExceptionResponse.Method) $($ExceptionResponse.ResponseUri) Returned $($ExceptionResponse.StatusCode) $ErrorContent"
                    }
                    else
                    {
                        $ErrorMessage="An error occurred $_"
                    }
                    Write-Verbose "[Get-AzureTableEntity] $ErrorMessage"
                    throw $ErrorMessage
                }
            }
        }
        elseif(-not [string]::IsNullOrEmpty($Response.Content))
        {
            $TableResult=$($Response.Content|ConvertFrom-Json)
            Write-Output $TableResult
        }
    }
    catch
    {
        #See if we can unwind an exception from a response
        if($_.Exception.Response -ne $null)
        {
            $ExceptionResponse=$_.Exception.Response
            $ErrorStream=$ExceptionResponse.GetResponseStream()
            $ErrorStream.Position=0
            $StreamReader = New-Object System.IO.StreamReader($ErrorStream)
            try
            {
                $ErrorContent=$StreamReader.ReadToEnd()
                $StreamReader.Close()
            }
            catch
            {
            }
            finally
            {
                $StreamReader.Close()
            }
            $ErrorMessage="Error: $($ExceptionResponse.Method) $($ExceptionResponse.ResponseUri) Returned $($ExceptionResponse.StatusCode) $ErrorContent"
        }
        else
        {
            $ErrorMessage="An error occurred $_"
        }
        Write-Verbose "[Get-AzureTableEntity] $ErrorMessage"
        throw $ErrorMessage
    }
}

<#
    .SYNOPSIS
        Inserts or Updates an Azure Table Entity
#>
Function Set-AzureTableEntity
{
    [CmdletBinding()]
    param
    ( 
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$TableName,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "table.core.windows.net",
        [Parameter(Mandatory = $true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Object[]]$InputObject,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ODataServiceVersion='3.0;Netfx',
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$ReturnDetail,
        [ValidateSet('application/json;odata=nometadata','application/json;odata=minimalmetadata','application/json;odata=fullmetadata')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ContentType='application/json;odata=nometadata'
    )
    BEGIN
    {
        $ReturnPref="return-no-content"
        if($ReturnDetail.IsPresent)
        {
            $ReturnPref='return-content'
        }
        $TableUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
        $TableUriBld=New-Object System.UriBuilder($TableUri)
        $TableUriBld.Path=$TableName      
        $TableToken=New-SharedKeySignature -Verb POST -Resource $TableUriBld.Uri -ContentType 'application/json' -AccessKey $AccessKey -ServiceType Table
        $TableHeaders=[ordered]@{
            'x-ms-version'=$ApiVersion
            'DataServiceVersion'=$ODataServiceVersion
            'Accept'=$ContentType
            'Date'=[DateTime]::UtcNow.ToString('R');
            'Prefer'=$ReturnPref;
            'Authorization'="SharedKey $($StorageAccountName):$TableToken"
        }
    }
    PROCESS
    {
        foreach ($item in $InputObject)
        {
            $RequestParams=@{
                Method='POST';
                Uri=$TableUriBld.Uri;
                Body=$($item|ConvertTo-Json);
                Headers=$TableHeaders;
                ContentType=$ContentType;
            }
            $Result=InvokeAzureStorageRequest @RequestParams
            if($ReturnDetail.IsPresent)
            {
                Write-Output $Result
            }
        }
    }
}

<#
    .SYNOPSIS
        Removes an Azure Table Entity
#>
Function Remove-AzureTableEntity
{
    [CmdletBinding()]
    param
    ( 
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$TableName,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$StorageAccountDomain = "table.core.windows.net",
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName=$true)]
        [string]$PartitionKey,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName=$true)]
        [string]$RowKey,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [string]$ETag='*',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessKey,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ODataServiceVersion='3.0;Netfx',
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$ReturnDetail
    )

    $TableUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $TableUriBld=New-Object System.UriBuilder($TableUri)
    $TableUriBld.Path="$TableName(PartitionKey='$PartitionKey',RowKey='$RowKey')"
       
    $TableToken=New-SharedKeySignature -Verb 'DELETE' -Resource $TableUriBld.Uri -ServiceType Table -IfMatch $ETag -AccessKey $AccessKey
    $TableHeaders=[ordered]@{
        'Date'=[DateTime]::UtcNow.ToString('R');
        'x-ms-version'=$ApiVersion
        'DataServiceVersion'=$ODataServiceVersion;
        'If-Match'=$ETag;
        'Authorization'="SharedKey $($StorageAccountName):$($TableToken)"
    }
    $RequestParams=@{
        Uri=$TableUriBld.Uri;
        Headers=$TableHeaders;
        ReturnHeaders=$ReturnDetail.IsPresent;
        Method='DELETE'
    }
    $Result=InvokeAzureStorageRequest @RequestParams
    if($ReturnDetail.IsPresent)
    {
        Write-Output $Result
    }
}

#endregion

#region BLOB

<#
    .SYNOPSIS
        Returns statistics for the blob service on the storage account
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the BLOB service API        
#>
Function Get-AzureBlobServiceStats
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )
    $BlobUri=GetStorageUri -AccountName "$StorageAccountName" -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $BlobUriBld=New-Object System.UriBuilder($BlobUri)
    $BlobUriBld.Query = "restype=service&comp=stats"
    $BlobHeaders = [ordered]@{
        'x-ms-date'=[DateTime]::UtcNow.ToString('R');
        "x-ms-version" = $ApiVersion;
    }
    $TokenParams=@{
        Verb="GET";
        Resource=$BlobUriBld.Uri;
        AccessKey=$AccessKey;
        Headers=$BlobHeaders;
    }
    $SasToken = New-SharedKeySignature @TokenParams
    $BlobUriBld.Host="$StorageAccountName-secondary.$StorageAccountDomain"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='GET';
        ExpandProperty='StorageServiceStats'
    }    
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $BlobResult=InvokeAzureStorageRequest @RequestParams
    Write-Output $BlobResult

}

<#
    .SYNOPSIS
        Retrieves the service properties for the storage account
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the BLOB service API        
#>
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )

    $BlobUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $BlobUriBld=New-Object System.UriBuilder($BlobUri)
    $BlobUriBld.Query = "restype=service&comp=properties"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='GET';
        ExpandProperty='StorageServiceProperties'
    }
    $BlobHeaders = [ordered]@{
        'x-ms-date'=[DateTime]::UtcNow.ToString('R');
        "x-ms-version" = $ApiVersion;
    }
    $TokenParams=@{
        Verb="GET";
        Resource=$BlobUriBld.Uri;
        AccessKey=$AccessKey;
        Headers=$BlobHeaders;
    }
    $SasToken = New-SharedKeySignature @TokenParams
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $BlobResult=InvokeAzureStorageRequest @RequestParams
    Write-Output $BlobResult
}

<#
    .SYNOPSIS
        Retrieves the metadata set for a BLOB container
#>
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
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ApiVersion="2016-05-31"
    )
    $BlobUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $BlobUriBld=New-Object System.UriBuilder($BlobUri)
    $BlobUriBld.Path="$ContainerName"
    $BlobUriBld.Query="restype=container&comp=metadata"
    $RequestParams=@{
        Method='Get';
        Uri=$BlobUriBld.Uri;
        ReturnHeaders=$true;
    }
    $BlobHeaders= @{
        "x-ms-date"=[DateTime]::UtcNow.ToString('R');
        "x-ms-version"=$ApiVersion;
    }
    $TokenParams=@{
        Verb="GET";
        Resource=$BlobUriBld.Uri;
        AccessKey=$AccessKey;
        Headers=$BlobHeaders;
    }
    $SasToken=New-SharedKeySignature  @TokenParams
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result=InvokeAzureStorageRequest @RequestParams
    Write-Output $Result
}

<#
    .SYNOPSIS
        Updates the metadata set for a BLOB container
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER ContainerName
        The storage account BLOB container name        
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests
#>
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )

    $BlobUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $BlobUriBld=New-Object System.UriBuilder($BlobUri)
    $BlobUriBld.Path = "$ContainerName"
    $BlobUriBld.Query = "restype=container&comp=metadata"
    Write-Verbose "[Set-AzureBlobContainerMetadata] Updating metadata $($Metadata.Keys) on $BlobUri"
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
    $SasToken=New-SharedKeySignature  -Verb PUT -Resource $BlobUriBld.Uri -AccessKey $AccessKey -Headers $BlobHeaders
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result = InvokeAzureStorageRequest @RequestParams
}

<#
    .SYNOPSIS
        Retrieves the list of BLOB(s) for a BLOB container
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER ContainerName
        The storage account BLOB container name        
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the BLOB service API 
#>
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
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ApiVersion="2016-05-31"
    )
    $BlobUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $BlobUriBld=New-Object System.UriBuilder($BlobUri)
    $BlobUriBld.Path="$ContainerName"
    $BlobUriBld.Query="restype=container&comp=list"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='Get';
        Headers=@{};
        ExpandProperty='EnumerationResults';
    }
    $TokenParams=@{
        Verb='GET';
        Resource=$BlobUriBld.Uri;
        Headers=@{
            "x-ms-date"=[DateTime]::UtcNow.ToString('R');
            "x-ms-version"=$ApiVersion;
        };
        AccessKey=$AccessKey;
    }
    Write-Verbose "[Get-AzureBlobContainerBlobs] Creating SAS Token for $($BlobUriBld.Uri)"
    $SasToken=New-SharedKeySignature  @TokenParams
    $TokenParams.Headers.Keys|ForEach-Object{$RequestParams.Headers[$_]=$TokenParams.Headers[$_]}
    $RequestParams.Headers.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $BlobResult=InvokeAzureStorageRequest @RequestParams
    Write-Verbose "[Get-AzureBlobContainerBlobs] Blob Response Endpoint:$($BlobResult.ServiceEndpoint) container $($BlobResult.ContainerName)"
    if($BlobResult.Blobs -ne $null -and $BlobResult.Blobs.Blob.Count -gt 0)
    {
        foreach ($Blob in $BlobResult.Blobs.Blob)
        {
            Write-Output $Blob
        }   
        $HasMore=-not [String]::IsNullOrEmpty($BlobResult.NextMarker)
        while ($HasMore)
        {
            #Set the marker in the URI
            $BlobUriBld.Query="restype=container&comp=list&marker=$($BlobResult.NextMarker)"
            Write-Verbose "[Get-AzureBlobContainerBlobs] Next set available @ $($BlobUriBld.Uri)"
            $RequestParams.Uri=$BlobUriBld.Uri
            $TokenParams.Resource=$BlobUriBld.Uri
            Write-Verbose "[Get-AzureBlobContainerBlobs] Creating SAS Token for $($BlobUriBld.Uri)"
            $SasToken=New-SharedKeySignature  @TokenParams        
            $RequestParams.Headers['Authorization']="SharedKey $($StorageAccountName):$($SasToken)"
            $BlobResult=InvokeAzureStorageRequest @RequestParams
            if($BlobResult.Blobs -ne $null -and $BlobResult.Blobs.Blob.Count -gt 0)
            {
                foreach ($NextBlob in $BlobResult.Blobs.Blob)
                {
                    Write-Output $NextBlob
                }
            }
            $HasMore=-not [String]::IsNullOrEmpty($BlobResult.NextMarker)
        }    
    }
}

<#
    .SYNOPSIS
        Downloads a file from a BLOB container
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER ContainerName
        The storage account BLOB container name 
    .PARAMETER BlobName
        The name of the BLOB to download
    .PARAMETER Uri
        The location of the item(s) to be downloaded
    .PARAMETER Destination
        The download destination folder path
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests
    .PARAMETER BufferSize
        The size of the download buffer
    .PARAMETER ApiVersion
        The version of the BLOB service API
#>
Function Receive-AzureBlob
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
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName='wordy')]
        [String]$BlobName,
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
        [String]$ApiVersion="2016-05-31",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='default')]
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ParameterSetName='wordy')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='public')]
        [int]$BufferSize=4096000
    )
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
            Write-Verbose "[Receive-AzureBlob] Requesting Azure Storage Blob $item from Storage Account:$StorageAccountName"
            $RequestParams=@{
                Uri=$item;
                Destination=$DestinationFile;
                BufferSize=$BufferSize;
            }
            if ($PSCmdlet.ParameterSetName -in 'default','wordy')
            {
                $BlobHeaders=@{
                    'x-ms-date'=[DateTime]::UtcNow.ToString('R');
                    'x-ms-version'=$ApiVersion;
                }
                $SasToken=New-SharedKeySignature -Verb GET -Resource $item -AccessKey $AccessKey -Headers $BlobHeaders
                $BlobHeaders.Add('Authorization',"SharedKey $($StorageAccountName):$($SasToken)")
                $RequestParams.Add('Headers',$BlobHeaders)
                Write-Verbose "[Receive-AzureBlob] Using SharedKey $SasToken"
            }
            DownloadBlob @RequestParams
        }
    }
}

<#
    .SYNOPSIS
        Uploads a file to a BLOB storage container
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER ContainerName
        The storage account BLOB container name
    .PARAMETER InputObject
        The item(s) to be uploaded
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the BLOB service API
    .PARAMETER BlobType
        The type of BLOB to be created
    .PARAMETER ContentType
        The type of content to be uploaded        
    .PARAMETER CalculateChecksum
        Whether to calculate and include an MD5 checksum
    .PARAMETER BlobType
        The type of BLOB to be created
#>
Function Send-AzureBlob
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$StorageAccountName,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$StorageAccountDomain = "blob.core.windows.net",        
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ContainerName='$root',
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [System.IO.FileInfo[]]$InputObject,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$AccessKey,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,        
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ApiVersion="2016-05-31",
        [ValidateSet('BlockBlob','PageBlob','AppendBlob')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$BlobType="BlockBlob",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ContentType,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [System.Collections.IDictionary]$Metadata,              
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$CalculateChecksum,
        [ValidateRange(1MB,4MB)]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [int]$PageBufferSize=4MB
    )
    PROCESS
    {
        foreach ($item in $InputObject)
        {
            $Checksum=[String]::Empty
            #Make sure this aligns across a 512-byte boundary
            if(($BlobType -eq 'PageBlob') -and ($item.Length % 512 -ne 0))
            {
                throw "Page BLOB(s) must align to 512 byte boundaries"
            }
            $BlobUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
            $BlobUriBld=New-Object System.UriBuilder($BlobUri)
            $BlobUriBld.Path="$($ContainerName.TrimEnd('/'))/$($item.Name)"
            $BlobHeaders=[ordered]@{}            
            if([String]::IsNullOrEmpty($ContentType))
            {
                $ContentType=[System.Web.MimeMapping]::GetMimeMapping($item.Name)
                Write-Verbose "[Send-AzureBlob] Inferring Content-Type:$ContentType"
            }
            $TokenParams=@{
                Resource=$BlobUriBld.Uri;
                Verb='PUT';
                ContentType=$ContentType;
                AccessKey=$AccessKey;
            }              
            if($BlobType -eq 'BlockBlob')
            {
                $TokenParams.Add('ContentLength',$item.Length)
                $BlobHeaders.Add('x-ms-blob-content-disposition',"attachment; filename=`"$($item.Name)`"")
            }
            elseif($BlobType -eq 'PageBlob')
            {
                $BlobHeaders.Add('x-ms-blob-content-length',$item.Length)
            }
            else
            {
                throw "AppendBlob not yet supported"
            }
            if($CalculateChecksum.IsPresent)
            {
                Write-Verbose "[Send-AzureBlob] Calculating MD5 Hash for $($item.Name)"
                $Checksum=$item|GetMd5Hash  
                Write-Verbose "[Send-AzureBlob] Calculated Hash $Checksum"
                $BlobHeaders.Add('x-ms-blob-content-md5',$Checksum)
                $TokenParams.Add('ContentMD5',$Checksum)
            }                         
            $BlobHeaders.Add('x-ms-blob-content-type',$ContentType)
            $BlobHeaders.Add('x-ms-blob-type',$BlobType)            
            if($Metadata -ne $null)
            {
                foreach ($MetaKey in $Metadata.Keys)
                {
                    $BlobHeaders.Add("x-ms-meta-$MetaKey",$Metadata[$MetaKey])
                }
            }

            $BlobHeaders.Add('x-ms-date',[DateTime]::UtcNow.ToString('R'))
            $BlobHeaders.Add('x-ms-version',$ApiVersion)
            $TokenParams.Add('Headers',$BlobHeaders)    
            $SasToken=New-SharedKeySignature @TokenParams
            if([String]::IsNullOrEmpty($Checksum) -eq $false)
            {
                $BlobHeaders.Add('Content-MD5',$Checksum)
            }
            $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
            if($BlobType -eq 'BlockBlob')
            {
                Write-Verbose "[Send-AzureBlob] Uploading Block Blob $($item.FullName) to $($BlobUriBld.Uri)"
                $FileBytes=[System.IO.File]::ReadAllBytes($item.FullName)
                $BlobHeaders.Add('Content-Length',$FileBytes.Length)
                $BlobHeaders.Add('Content-Type',$ContentType)
                $RequestParams=@{
                    Uri=$BlobUriBld.Uri;
                    Method='PUT';
                    Headers=$BlobHeaders;
                    Body=$FileBytes;
                }
                $Response=Invoke-WebRequest @RequestParams
                Write-Verbose "[Send-AzureBlob] Upload Completed $($Response.StatusCode) - $($Response.StatusDescription)"
                Write-Output $Response.Headers
            }
            else
            {                
                Write-Verbose "[Send-AzureBlob] Creating Page Blob $($item.FullName) @ $($BlobUriBld.Uri) of size $($item.Length/1MB)"
                Write-Progress -Activity "Creating Page BLOB" -Status "Creating $($item.FullName) @ $($BlobUriBld.Uri) of size $($item.Length/1MB) MB"
                $BlobHeaders.Add('Content-Type',$ContentType)
                $RequestParams=@{
                    Uri=$BlobUriBld.Uri;
                    Method='PUT';
                    Headers=$BlobHeaders;
                    ReturnHeaders=$true;
                    ErrorAction='Stop';
                }
                $Response=InvokeAzureStorageRequest @RequestParams
                Write-Verbose "[Send-AzureBlob] Creating Page Blob $($item.FullName) @ $($BlobUriBld.Uri) of size $($item.Length/1MB) - Success!"
                #Now we can start appending the pages
                $InputStream=[System.IO.Stream]::Null
                $Stopwatch=New-Object System.Diagnostics.Stopwatch
                try
                {
                    $BytesWritten=0
                    Write-Verbose "[Send-AzureBlob] Appending File Stream to Page BLOB @ $($BlobUriBld.Uri) - Page Size:$PageBufferSize"
                    $Buffer=New-Object System.Byte[]($PageBufferSize)
                    $InputStream=$item.OpenRead()
                    $BytesRead=$InputStream.Read($Buffer,$BytesWritten,$PageBufferSize)
                    while ($BytesRead -gt 0)
                    {
                        $Stopwatch.Start()
                        $RangeStart=$BytesWritten
                        $BytesWritten+=$BytesRead
                        $Page=$Buffer[0..$($BytesRead-1)]
                        $PutPageResult=Set-AzureBlobPage -Page $Page -StorageAccountName $StorageAccountName -StorageAccountDomain $StorageAccountDomain `
                            -ContainerName $ContainerName -BlobItem $item.Name -AccessKey $AccessKey -ApiVersion $ApiVersion `
                            -UseHttp:$UseHttp -CalculateChecksum:$CalculateChecksum -RangeStart $RangeStart -RangeEnd $BytesWritten
                        $Speed=[Math]::Round($BytesWritten/1MB/$Stopwatch.Elapsed.TotalSeconds,2)
                        $Stopwatch.Stop()                            
                        $DetailedStatus="[Send-AzureBlob] ETag:$($PutPageResult.ETag) Transfer-Encoding:$($PutPageResult.'Transfer-Encoding') Request Id:$($PutPageResult.'x-ms-request-id')"
                        Write-Progress -Activity "Updating Page BLOB" -Status "Updating $($BlobUriBld.Uri) $([Math]::Round($BytesWritten/1MB)) MB written - ($Speed mb/s)" -PercentComplete $($BytesWritten/$item.Length * 100)
                        $BytesRead=$InputStream.Read($Buffer,0,$PageBufferSize)
                    }
                }
                catch
                {
                    throw $_
                }
                finally
                {
                    $Stopwatch.Stop()
                    Write-Progress -Activity "Creating Page BLOB" -Completed
                    if($InputStream -ne $null)
                    {
                        $InputStream.Dispose()
                    }
                }
            }
        }
    }
}

<#
    .SYNOPSIS
        Updates the content of a Page BLOB
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER ContainerName
        The storage account BLOB container name
    .PARAMETER BlobItem
        The name of the item to be uploaded
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        Tnh
    .PARAMETER RangeStart
        The byte position of the page range
    .PARAMETER RangeEnd
        The ending byte position of the page range        
    .PARAMETER ClearRange
        Clear the range of bytes
    .PARAMETER CalculateChecksum
        Calculate an MD5 checksum of the content
#>
Function Set-AzureBlobPage
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='clear')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='update')]
        [String]$StorageAccountName,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='clear')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='update')]
        [String]$StorageAccountDomain = "blob.core.windows.net",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='clear')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='update')]
        [String]$ContainerName='$root',
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='clear')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='update')]
        [String]$BlobItem,        
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='clear')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='update')]
        [long]$RangeStart,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='clear')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='update')]
        [long]$RangeEnd,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='update')]
        [System.Byte[]]$Page,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='clear')]
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='update')]
        [String]$AccessKey,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='clear')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='update')]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='clear')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='update')]
        [String]$ApiVersion="2016-05-31",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='clear')]
        [Switch]$ClearRange,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='update')]
        [Switch]$CalculateChecksum
    )
    $Checksum=[String]::Empty

    if($PSCmdlet.ParameterSetName -eq 'update')
    {
        $WriteAction='Update'
        $ContentLength=$Page.Length
        if($CalculateChecksum.IsPresent)
        {
            $Hasher= New-Object System.Security.Cryptography.MD5CryptoServiceProvider
            $Checksum=[System.Convert]::ToBase64String($Hasher.ComputeHash($Page))
        }
    }
    else
    {
        $WriteAction='Clear'
        $ContentLength=0
    }
    $BlobUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $BlobUriBld=New-Object System.UriBuilder($BlobUri)   
    $BlobUriBld.Path="$($ContainerName.TrimEnd('/'))/$($BlobItem)"
    $BlobUriBld.Query="comp=page"
    Write-Verbose "[Set-AzureBlobPage] Azure BLOB Page Action:$WriteAction $($BlobUriBld.Uri) $RangeStart,$RangeEnd"
    $TokenParams=@{
        Resource=$BlobUriBld.Uri;
        Verb='PUT';
        AccessKey=$AccessKey;
        #RangeStart=$RangeStart;
        #RangeEnd=$RangeEnd;
    }
    if($ContentLength -gt 0)
    {
        $TokenParams.Add('ContentLength',$ContentLength)
    }
    $BlobHeaders=[ordered]@{
        'x-ms-blob-type'="PageBlob";
        'x-ms-date'=[System.DateTime]::UtcNow.ToString('R');
        'x-ms-page-write'=$WriteAction;
        'x-ms-range'="bytes=$RangeStart-$($RangeEnd-1)";
        'x-ms-version'=$ApiVersion;
    }
    if([String]::IsNullOrEmpty($Checksum) -eq $false)
    {
        $TokenParams.Add('ContentMD5',$Checksum)
    }
    $TokenParams.Add('Headers',$BlobHeaders)
    $StopWatch=New-Object System.Diagnostics.Stopwatch
    try
    {
        $SasToken=New-SharedKeySignature @TokenParams
        $StopWatch.Start()

        if([String]::IsNullOrEmpty($Checksum) -eq $false)
        {
            $BlobHeaders.Add('Content-MD5',$Checksum)
        }
        $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$SasToken")
        $BlobHeaders.Add('Content-Length',$ContentLength)
        $RequestParams=@{
            Uri=$BlobUriBld.Uri;
            Method='PUT';
            Headers=$BlobHeaders;
            Body=$Page;
            ReturnHeaders=$true
        }
        $Result=InvokeAzureStorageRequest @RequestParams
        $StopWatch.Stop()
        Write-Verbose "[Set-AzureBlobPage] $($BlobUriBld.Uri) Page Action:$WriteAction Range:$RangeStart - $RangeEnd bytes succeeded in $($StopWatch.Elapsed.TotalSeconds) secs."
        Write-Output $Result        
    }
    catch
    {
        throw $_
    }
    finally
    {
        $StopWatch.Stop()
    }

}

<#
    .SYNOPSIS
        Retrieves the list of containers for the storage account
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the BLOB service API
#>
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )

    $BlobUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $BlobUriBld=New-Object System.UriBuilder($BlobUri)
    $BlobUriBld.Query = "comp=list"
    $BlobHeaders = [ordered]@{
        "x-ms-date" = [DateTime]::UtcNow.ToString('R');
        "x-ms-version" = $ApiVersion;
    }
    $TokenParams=@{
        Verb="GET";
        Resource=$BlobUriBld.Uri;
        AccessKey=$AccessKey;
        Headers=$BlobHeaders;
    }
    $SasToken = New-SharedKeySignature @TokenParams    
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='GET';
        Headers=$BlobHeaders;
    }    
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

<#
    .SYNOPSIS
        Retrieves the properties for a Blob container
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER ContainerName
        The name of the container        
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the BLOB service API        
#>
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
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [String]$ApiVersion="2016-05-31"
    )
    $BlobUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $BlobUriBld=New-Object System.UriBuilder($BlobUri)
    $BlobUriBld.Path="$ContainerName"
    $BlobUriBld.Query="restype=container"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='GET';
        ReturnHeaders=$true;
    }
    $BlobHeaders= [ordered]@{
        "x-ms-date"=[DateTime]::UtcNow.ToString('R');
        "x-ms-version"=$ApiVersion;
    }
    $TokenParams=@{
        Verb="GET";
        Resource=$BlobUriBld.Uri;
        AccessKey=$AccessKey;
        Headers=$BlobHeaders;
    }
    $SasToken = New-SharedKeySignature @TokenParams
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result=InvokeAzureStorageRequest @RequestParams
    Write-Output $Result
}

<#
    .SYNOPSIS
        Retrieves the public Access Control for a Blob container
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER ContainerName
        The name of the container        
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the BLOB service API        
#>
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )
    $BlobUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $BlobUriBld=New-Object System.UriBuilder($BlobUri)
    $BlobUriBld.Path = "$ContainerName"
    $BlobUriBld.Query = "restype=container&comp=acl"
    $RequestParams=@{
            Uri=$BlobUriBld.Uri;
            Method='GET';
            ReturnHeaders=$true;
    }
    $BlobHeaders = [ordered]@{
        "x-ms-date" = [DateTime]::UtcNow.ToString('R');
        "x-ms-version" = $ApiVersion;
    }    
    $TokenParams=@{
        Verb="GET";
        Resource=$BlobUriBld.Uri;
        AccessKey=$AccessKey;
        Headers=$BlobHeaders;
    }
    $SasToken = New-SharedKeySignature @TokenParams
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result = InvokeAzureStorageRequest @RequestParams
    Write-Output $Result.'x-ms-blob-public-access'
}

<#
    .SYNOPSIS
        Set the public access control for a blob container
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER ContainerName
        The name of the container        
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the BLOB service API
    .PARAMETER AccessLevel
        The public access level for the container
#>
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )

    $BlobUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $BlobUriBld=New-Object System.UriBuilder($BlobUri)
    $BlobUriBld.Path = "$ContainerName"
    $BlobUriBld.Query = "restype=container&comp=acl"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='PUT';
        ReturnHeaders=$true;
    }
    $BlobHeaders = [ordered]@{
        "x-ms-date" = [datetime]::UtcNow.ToString('R');
        "x-ms-version" = $ApiVersion;
    }
    if($AccessLevel -ne 'private')
    {
        $BlobHeaders.Add('x-ms-blob-public-access',$AccessLevel)
    }
    $TokenParams=@{
        Verb="PUT";
        Resource=$BlobUriBld.Uri;
        AccessKey=$AccessKey;
        Headers=$BlobHeaders;
    }
    $SasToken = New-SharedKeySignature @TokenParams
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

<#
    .SYNOPSIS
        Creates a new BLOB container
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER ContainerName
        The name of the container        
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the BLOB service API
#>
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )
    $BlobUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $BlobUriBld=New-Object System.UriBuilder($BlobUri)
    $BlobUriBld.Path = $ContainerName.ToLower()
    $BlobUriBld.Query = "restype=container"

    Write-Verbose "[New-AzureBlobContainer] Creating new BLOB container $BlobUri"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='PUT';
        ReturnHeaders=$true;
    }
    $BlobHeaders = [ordered]@{
        "x-ms-date" = [DateTime]::UtcNow.ToString('R');
        "x-ms-version" = $ApiVersion;
    }
    $TokenParams=@{
        Verb="PUT";
        Resource=$BlobUriBld.Uri;
        AccessKey=$AccessKey;
        Headers=$BlobHeaders;
    }
    $SasToken = New-SharedKeySignature @TokenParams
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result = InvokeAzureStorageRequest @RequestParams
    Write-Output $Result
}

<#
    .SYNOPSIS
        Deletes a new BLOB container
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER ContainerName
        The name of the container        
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the BLOB service API
#>
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )
    $BlobUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $BlobUriBld=New-Object System.UriBuilder($BlobUri)
    $BlobUriBld.Path = "$ContainerName"
    $BlobUriBld.Query = "restype=container"
    
    Write-Verbose "[Remove-AzureBlobContainer] Removing BLOB Container $BlobUri"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='DELETE';
        ReturnHeaders=$true;
    }
    $BlobHeaders = [ordered]@{
        "x-ms-date" = [DateTime]::UtcNow.ToString('R');
        "x-ms-version" = $ApiVersion;
    }
    $TokenParams=@{
        Verb="DELETE";
        Resource=$BlobUriBld.Uri;
        AccessKey=$AccessKey;
        Headers=$BlobHeaders;
    }
    $SasToken = New-SharedKeySignature @TokenParams
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result = InvokeAzureStorageRequest @RequestParams
    Write-Output $Result
}

<#
    .SYNOPSIS
        Creates a new BLOB container lease
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER ContainerName
        The name of the container        
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the BLOB service API
#>
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = "2016-05-31"
    )

    $BlobUri=GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent
    $BlobUriBld=New-Object System.UriBuilder($BlobUri)
    $BlobUriBld.Path = "$ContainerName"
    $BlobUriBld.Query = "comp=lease&restype=container"

    Write-Verbose "[Set-AzureBlobContainerLease] Performing lease action:$LeaseAction on $BlobUri"
    $RequestParams=@{
        Uri=$BlobUriBld.Uri;
        Method='PUT';
        ReturnHeaders=$true;
    }

    $BlobHeaders = [ordered]@{
        "x-ms-date" = [datetime]::UtcNow.ToString('R');
    }
    $BlobHeaders.Add('x-ms-lease-action',$LeaseAction.ToLower())
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
    $BlobHeaders.Add("x-ms-version",$ApiVersion)
    $TokenParams=@{
        Verb="PUT";
        Resource=$BlobUriBld.Uri;
        AccessKey=$AccessKey;
        Headers=$BlobHeaders;
    }
    $SasToken = New-SharedKeySignature @TokenParams
    $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
    $RequestParams.Add('Headers',$BlobHeaders)
    $Result = InvokeAzureStorageRequest @RequestParams
    Write-Output $Result
}

<#
    .SYNOPSIS
        Retrieves the metadata for a BLOB
    .PARAMETER Uri
        The URI of the BLOB
    .PARAMETER BlobName
        The name of the BLOB
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER ContainerName
        The name of the container        
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the BLOB service API
#>
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
        [Parameter(Mandatory=$false,ParameterSetName='indirect',ValueFromPipelineByPropertyName=$true)]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ApiVersion="2016-05-31"
    )
    PROCESS
    {
        if($PSCmdlet.ParameterSetName -eq 'indirect')
        {
            $InputObject=@(GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent)
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
            $TokenParams=@{
                Verb="GET";
                Resource=$BlobUriBld.Uri;
                AccessKey=$AccessKey;
                Headers=$BlobHeaders;
            }
            $SasToken = New-SharedKeySignature @TokenParams
            $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
            $RequestParams.Add('Headers',$BlobHeaders)
            $Result=InvokeAzureStorageRequest @RequestParams
            Write-Output $Result
        }
    }
}

<#
    .SYNOPSIS
        Retrieves the metadata for a BLOB
    .PARAMETER Uri
        The URI of the BLOB
    .PARAMETER BlobName
        The name of the BLOB
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER ContainerName
        The name of the container        
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The version of the BLOB service API
#>
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
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ApiVersion="2016-05-31"
    )
    PROCESS
    {
        if($PSCmdlet.ParameterSetName -eq 'indirect')
        {
            $InputObject=@(GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent)
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
            $BlobHeaders= [ordered]@{
                "x-ms-date"=[DateTime]::UtcNow.ToString('R');
                "x-ms-version"=$ApiVersion;
            }
            $TokenParams=@{
                Verb="GET";
                Resource=$BlobUriBld.Uri;
                AccessKey=$AccessKey;
                Headers=$BlobHeaders;
            }
            $SasToken = New-SharedKeySignature @TokenParams
            $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
            $RequestParams.Add('Headers',$BlobHeaders)
            $Result=InvokeAzureStorageRequest @RequestParams
            Write-Output $Result
        }
    }
}

<#
    .SYNOPSIS
        Sets metadata on the specified BLOB
    .PARAMETER Uri
        The URI of the BLOB
    .PARAMETER BlobName
        The name of the BLOB
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER ContainerName
        The name of the container
    .PARAMETER Metadata
        Key-value pairs for BLOB metadata
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The storage service API version
#>
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
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ApiVersion="2016-05-31"
    )

    PROCESS
    {
        if($PSCmdlet.ParameterSetName -eq 'indirect')
        {
            $InputObject=@(GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent)
        }
        foreach($item in $InputObject)
        {
            Write-Verbose "[Set-AzureBlobMetadata] Setting metadata $($Metadata.Keys) on $item"
            if([String]::IsNullOrEmpty($StorageAccountName))
            {
                $StorageAccountName=$item.Host.Split('.')|Select-Object -First 1
            }
            $BlobUriBld=New-Object System.UriBuilder($item)
            $BlobUriBld.Query="comp=metadata"
            $RequestParams=@{
                Uri=$BlobUriBld.Uri;
                Method='PUT';
                ReturnHeaders=$true;
            }
            $BlobHeaders= [ordered]@{
                "x-ms-date"=[DateTime]::UtcNow.ToString('R');
            }
            foreach($MetaKey in ($Metadata.Keys|Sort-Object))
            {
                $BlobHeaders.Add("x-ms-meta-$MetaKey",$Metadata[$MetaKey])
            }
            $BlobHeaders.Add("x-ms-version",$ApiVersion)
            $TokenParams=@{
                Verb="PUT";
                Resource=$BlobUriBld.Uri;
                AccessKey=$AccessKey;
                Headers=$BlobHeaders;
            }
            $SasToken = New-SharedKeySignature @TokenParams
            $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
            $RequestParams.Add('Headers',$BlobHeaders)
            $Result=InvokeAzureStorageRequest @RequestParams
            Write-Output $Result
        }
    }
}

<#
    .SYNOPSIS
        Creates a new snapshot of the specified BLOB
    .PARAMETER Uri
        The URI of the BLOB
    .PARAMETER BlobName
        The name of the BLOB
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER ContainerName
        The name of the container
    .PARAMETER AccessKey
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The storage service API version
#>
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
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ApiVersion="2016-05-31"
    )
    PROCESS
    {
        if($PSCmdlet.ParameterSetName -eq 'indirect')
        {
            $InputObject=@(GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent)
        }
        foreach($item in $InputObject)
        {
            Write-Verbose "[New-AzureBlobSnapshot] Creating new snapshot for $($item)"
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
            $BlobHeaders= [ordered]@{
                "x-ms-date"=[DateTime]::UtcNow.ToString('R');
                "x-ms-version"=$ApiVersion;
            }
            $TokenParams=@{
                Verb="PUT";
                Resource=$BlobUriBld.Uri;
                AccessKey=$AccessKey;
                Headers=$BlobHeaders;
            }
            $SasToken = New-SharedKeySignature @TokenParams            
            $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
            $RequestParams.Add('Headers',$BlobHeaders)
            $Result=InvokeAzureStorageRequest @RequestParams
            Write-Output $Result
        }
    }
}

<#
    .SYNOPSIS
        Deletes the specified BLOB
    .PARAMETER Uri
        The URI of the BLOB
    .PARAMETER BlobName
        The name of the BLOB
    .PARAMETER StorageAccountName
        The storage account name
    .PARAMETER StorageAccountDomain
        The FQDN for the storage account service
    .PARAMETER ContainerName
        The name of the container
    .PARAMETER OnlySnapshots
        Only delete the BLOB snapshots
    .PARAMETER DeleteSnapshots
        Include the snapshots
    .PARAMETER AccessKey    
        The storage service access key
    .PARAMETER UseHttp
        Use Insecure requests 
    .PARAMETER ApiVersion
        The storage service API version
#>
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
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [Switch]$UseHttp,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [Guid]$LeaseId,
        [Parameter(Mandatory=$false,ParameterSetName='indirect')]
        [Parameter(Mandatory=$false,ParameterSetName='direct')]
        [Switch]$DeleteSnapshots,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Switch]$OnlySnapshots,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='direct')]
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ParameterSetName='indirect')]
        [String]$ApiVersion="2016-05-31"
    )
    PROCESS
    {
        if($PSCmdlet.ParameterSetName -eq 'indirect')
        {
            $InputObject=@(GetStorageUri -AccountName $StorageAccountName -StorageServiceFQDN $StorageAccountDomain -IsInsecure $UseHttp.IsPresent)
        }
        foreach($item in $InputObject)
        {
            Write-Verbose "[Remove-AzureBlob] Removing BLOB $($item)"
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
            $BlobHeaders= [ordered]@{
                "x-ms-date"=[DateTime]::UtcNow.ToString('R');
                "x-ms-version"=$ApiVersion;
            }
            if($LeaseId -ne $null -and $LeaseId -ne [Guid]::Empty)
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
            $TokenParams=@{
                Verb="DELETE";
                Resource=$BlobUriBld.Uri;
                AccessKey=$AccessKey;
                Headers=$BlobHeaders;
            }
            $SasToken = New-SharedKeySignature @TokenParams
            $BlobHeaders.Add("Authorization","SharedKey $($StorageAccountName):$($SasToken)")
            $RequestParams.Add('Headers',$BlobHeaders)
            $Result=InvokeAzureStorageRequest @RequestParams
            Write-Output $Result
        }
    }
}

#endregion