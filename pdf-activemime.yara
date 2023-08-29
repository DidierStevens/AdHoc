rule rule_pdf_activemime {
    meta:
        author = "Didier Stevens"
        date = "2023/08/29"
        version = "0.0.1"
        samples = "5b677d297fb862c2d223973697479ee53a91d03073b14556f421b3d74f136b9d,098796e1b82c199ad226bff056b6310262b132f6d06930d3c254c57bdf548187,ef59d7038cfd565fd65bae12588810d5361df938244ebad33b71882dcf683058"
        description = "look for files that start with %PDF- and contain BASE64 encoded string ActiveMim (QWN0aXZlTWlt), possibly obfuscated with extra whitespace characters"
        usage = "if you don't have to care about YARA performance warnings, you can uncomment string $base64_ActiveMim0 and remove all other $base64_ActiveMim## strings"
    strings:
        $pdf = "%PDF-"
//        $base64_ActiveMim0 = /[ \t\r\n]*Q[ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim1 = /Q  [ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim2 = /Q \t[ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim3 = /Q \r[ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim4 = /Q \n[ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim5 = /Q\t [ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim6 = /Q\t\t[ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim7 = /Q\t\r[ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim8 = /Q\t\n[ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim9 = /Q\r [ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim10 = /Q\r\t[ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim11 = /Q\r\r[ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim12 = /Q\r\n[ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim13 = /Q\n [ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim14 = /Q\n\t[ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim15 = /Q\n\r[ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim16 = /Q\n\n[ \t\r\n]*W[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim17 = /QW [ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim18 = /QW\t[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim19 = /QW\r[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim20 = /QW\n[ \t\r\n]*N[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
        $base64_ActiveMim21 = /QWN[ \t\r\n]*0[ \t\r\n]*a[ \t\r\n]*X[ \t\r\n]*Z[ \t\r\n]*l[ \t\r\n]*T[ \t\r\n]*W[ \t\r\n]*l[ \t\r\n]*t/
    condition:
        $pdf at 0 and any of ($base64_ActiveMim*)
}
