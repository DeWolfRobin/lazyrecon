#!/bin/bash

red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`


domain=

usage() { echo -e "Usage: $0 -d domain [-e]\n  Select -e to specify excluded domains\n " 1>&2; exit 1; }

while getopts "sd:" o; do
    case "${o}" in
        d)
            domain=${OPTARG}
            ;;
        e)
            excluded=${OPTARG}
            ;;

        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [ -z "${domain}" ] ; then
   usage
fi

discovery(){
  hostalive $domain
  screenshot $domain
  cleanup $domain
  cat ./$domain/$foldername/responsive-$(date +"%Y-%m-%d")-codes.txt | sort -u | while read line; do
    sleep 1
    subdomain=$(echo "$line" | awk '{print $1}')


#we pass subdomain with status code to dirsearcher so we can define the right arguments

    dirsearcher $line

#we pass domain value and subdomain without statuscode to report

    report $domain $subdomain
    echo "report generated for $line "
    sleep 1
  done

}


cleanup(){
  cd ./$domain/$foldername/screenshots/
  rename 's/_/-/g' -- *
  cd $path
}

hostalive(){

#read from file alldomains and check if host is alive on port 80 and 443 and save results in two files responsive-date.txt and responsive-date-codes.txt
#the format for responsive-dates-codes.txt is as follows test.example.com 443
#we need to store these codes to pass arguments correctly to dirsearch
  cat ./$domain/$foldername/alldomains.txt  | sort -u | while read line; do
        httpcl=$(curl --write-out %{http_code} --silent --output /dev/null -m 5 http://$line)
        httpssl=$(curl --write-out %{http_code} --silent --output /dev/null -m 5 -k https://$line)
    if [[ $httpcl = 000 && $httpssl = 000 ]]; then
      echo "$line was unreachable"
      echo "$line" >> ./$domain/$foldername/unreachable.txt
    elif [[ $httpcl = 000 && $httpssl != 000 ]]; then
      echo "$line is up on port 443"
      echo "$line 443" >> ./$domain/$foldername/responsive-$(date +"%Y-%m-%d")-codes.txt
      echo "$line" >> ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt
    else
      echo "$line is up on port 80"
      echo "$line 80" >> ./$domain/$foldername/responsive-$(date +"%Y-%m-%d")-codes.txt
      echo "$line" >> ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt
    fi
  done
}

screenshot(){
    echo "taking a screenshot of $line"
    python ~/tools/webscreenshot/webscreenshot.py -o ./$domain/$foldername/screenshots/ -i ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt --timeout=10 -m
}

recon(){

  echo "${green}Recon started on $domain ${reset}"
  echo "Listing subdomains using sublister..."
  python ~/tools/Sublist3r/sublist3r.py -d $domain -t 10 -v -o ./$domain/$foldername/$domain.txt > /dev/null
  echo "Checking certspotter..."
  curl -s https://certspotter.com/api/v0/certs\?domain\=$domain | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $domain >> ./$domain/$foldername/$domain.txt
  nsrecords $domain
  echo "Looking up ipaddress space..."
  asnlookup $domain
  echo "Starting discovery..."
  discovery $domain
  cat ./$domain/$foldername/$domain.txt | sort -u > ./$domain/$foldername/$domain.txt


}
asnlookup(){
#find ip address space of organization this is not bulletproof but it should work for now


 dm="$domain"
 org=$(echo "${dm%%.*}")
#get domain and remove .* example if we pass hackerone.com this will remove .com and the result would be hackerone
#we will use this to run asnlookup results will be stored to ipaddress.txt

 python ~/tools/asnlookup/asnlookup.py -o $org |  grep -E "*/[0-9]" > ./$domain/$foldername/ipaddress.txt

 if [[ -s "./$domain/$foldername/ipaddress.txt" ]]; then
    echo "${red}Ip address space found${reset}"
    cat ./$domain/$foldername/ipaddress.txt
    else
    echo "Could not find ip address space :/";
    fi

}

dirsearcher(){

#now that we have the subdomain with port 80/443 we can do simple check and then set urlscheme http or https
#note that if target is alive on both ports dirsearcher will default to port 80
#this is not bulletproof as it might overload the server because of concurrent connections on https  considering to implement other tools instead turbo intruder/ gobuster
  statcode=$(echo "$line" | awk '{print $2}')
  if [[ "$statcode" == "80" ]]; then
  urlscheme=http
  else
  urlscheme=https
  fi
  testdm=$(echo "$line" | awk '{print $1}')

  python3 ~/tools/dirsearch/dirsearch.py -e php,asp,aspx,jsp,html,zip,jar -u $urlscheme://$testdm
}
crtsh(){

# query crtsh and resolve results with massdns this is more convenient as it might reveal old dns records
# read reults from sulblist3r+certspotter and resolve using massdns again looking for old dns records
 ~/massdns/scripts/ct.py $domain | ~/massdns/bin/massdns -r ~/massdns/lists/resolvers.txt -t A -q -o S -w  ./$domain/$foldername/crtsh.txt
 cat ./$domain/$foldername/$domain.txt | ~/massdns/bin/massdns -r ~/massdns/lists/resolvers.txt -t A -q -o S -w  ./$domain/$foldername/domaintemp.txt
}
mass(){
# we run massdns with default settings we don't care about wildcard dns and bad resolvers we will clean up once the scan finishes
 ~/massdns/scripts/subbrute.py ~/massdns/all.txt $domain | ~/massdns/bin/massdns -r ~/massdns/lists/resolvers.txt -t A -q -o S | grep -v 142.54.173.92 > ./$domain/$foldername/mass.txt
}
nsrecords(){

#this function will call crt.sh and massdns then it will look into results and remove any problems related to bad resolvers
#this function main obective is to find any azure , aws takeovers or any sort of old dns takeovers
                echo "Checking http://crt.sh"
                crtsh $domain > /dev/null
                echo "Starting Massdns Subdomain discovery this may take a while"
                mass $domain > /dev/null
                echo "Massdns finished..."
                echo "${green}Started dns records check...${reset}"
                echo "Looking into CNAME Records..."
#we will store all of the results from the previous tools to single temporary file

                cat ./$domain/$foldername/mass.txt >> ./$domain/$foldername/temp.txt
                cat ./$domain/$foldername/domaintemp.txt >> ./$domain/$foldername/temp.txt
                cat ./$domain/$foldername/crtsh.txt >> ./$domain/$foldername/temp.txt

#read the temporary file and detect wildcard dns remember we only need the first occurence of each domain
#save results to cleantemp.txt
                cat ./$domain/$foldername/temp.txt | awk '{print $3}' | sort -u | while read line; do
                wildcard=$(cat ./$domain/$foldername/temp.txt | grep -m 1 $line)
                echo "$wildcard" >> ./$domain/$foldername/cleantemp.txt
                done

#read the cleantemp grep for lines with CNAME then save it to a file

                cat ./$domain/$foldername/cleantemp.txt | grep CNAME >> ./$domain/$foldername/cnames.txt
                cat ./$domain/$foldername/cnames.txt | sort -u | while read line; do

#since the file output is as follows test.exmple.com. CNAME something.aws.com.
#we will take the first part run host and if the results is NXDOMAIN that mean we just found an old dns record and possible takeover
#save results to pos.txt

                hostrec=$(echo "$line" | awk '{print $1}')
                if [[ $(host $hostrec | grep NXDOMAIN) != "" ]]
                then
                echo "${red}Check the following domain for NS takeover:  $line ${reset}"
                echo "$line" >> ./$domain/$foldername/pos.txt
                else
                echo -ne "working on it...\r"
                fi
                done
                sleep 1
                cat ./$domain/$foldername/$domain.txt > ./$domain/$foldername/alldomains.txt
                cat ./$domain/$foldername/cleantemp.txt | awk  '{print $1}' | while read line; do

#we take the first part of line test.exmple.com. CNAME something.aws.com. and remove the trailing dot

                x="$line"
                echo "${x%?}" >> ./$domain/$foldername/alldomains.txt
                done
                echo  "${green}Total of $(wc -l ./$domain/$foldername/alldomains.txt | awk '{print $1}') subdomains were found${reset}"
                sleep 1

        }

report(){

  touch ./$domain/$foldername/reports/$subdomain.html
  echo "<title> report for $line </title>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<html>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<head>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<link rel=\"stylesheet\" href=\"https://fonts.googleapis.com/css?family=Mina\" rel=\"stylesheet\">" >> ./$domain/$foldername/reports/$subdomain.html
  echo "</head>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<body><meta charset=\"utf-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css\"> <script src=\"https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js\"></script> <script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js\"></script></body>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<div class=\"jumbotron text-center\"><h1> Recon Report for <a/href=\"http://$line.com\">$line</a></h1>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<p> Generated by <a/href=\"https://github.com/nahamsec/lazyrecon\"> LazyRecon</a> on $(date) </p></div>" >> ./$domain/$foldername/reports/$subdomain.html


  echo "<div clsas=\"row\">" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<div class=\"col-sm-6\">" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Dirsearch</h2></div>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/reports/$subdomain.html
  cat ~/tools/dirsearch/reports/$subdomain/* | while read nline; do
  status_code=$(echo "$nline" | awk '{print $1}')
  url=$(echo "$nline" | awk '{print $3}')
 if [[ "$status_code" == *20[012345678]* ]]; then
    echo "<span style='background-color:#00f93645;'><a href='$url'>$nline</a></span>" >> ./$domain/$foldername/reports/$subdomain.html
  elif [[ "$status_code" == *30[012345678]* ]]; then
    echo "<span style='background-color:#f9f10045;'><a href='$url'>$nline</a></span>" >> ./$domain/$foldername/reports/$subdomain.html
  elif [[ "$status_code" == *40[012345678]* ]]; then
    echo "<span style='background-color:#0000cc52;'><a href='$url'>$nline</a></span>" >> ./$domain/$foldername/reports/$subdomain.html
  elif [[ "$status_code" == *50[012345678]* ]]; then
    echo "<span style='background-color:#f9000045;'><a href='$url'>$nline</a></span>" >> ./$domain/$foldername/reports/$subdomain.html
  else
    echo "<span>$line</span>" >> ./$domain/$foldername/reports/$subdomain.html
  fi
done

  echo "</pre>   </div>" >> ./$domain/$foldername/reports/$subdomain.html


  echo "<div class=\"col-sm-6\">" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Screeshot</h2></div>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "Port 80                              Port 443" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<img/src=\"../screenshots/http-$subdomain-80.png\" style=\"max-width: 500px;\"> <img/src=\"../screenshots/https-$subdomain-443.png\" style=\"max-width: 500px;\"> <br>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "</pre>" >> ./$domain/$foldername/reports/$subdomain.html

  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Dig Info</h2></div>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/reports/$subdomain.html
  dig $subdomain >> ./$domain/$foldername/reports/$subdomain.html
  echo "</pre>" >> ./$domain/$foldername/reports/$subdomain.html

  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Host Info</h1></div>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/reports/$subdomain.html
  host $subdomain >> ./$domain/$foldername/reports/$subdomain.html
  echo "</pre>" >> ./$domain/$foldername/reports/$subdomain.html


  echo "<div style=\"font-family: 'Mina', serif;\"><h2>Response Header</h1></div>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<pre>" >> ./$domain/$foldername/reports/$subdomain.html
  curl -sSL -D - $subdomain  -o /dev/null >> ./$domain/$foldername/reports/$subdomain.html
  echo "</pre>" >> ./$domain/$foldername/reports/$subdomain.html


  echo "<div style=\"font-family: 'Mina', serif;\"><h1>Nmap Results</h1></div>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "<pre style='display: block;'>" >> ./$domain/$foldername/reports/$subdomain.html
  echo "nmap -sV -T3 -Pn -p3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,7447,7080,8880,8983,5673,7443,19000,19080" >> ./$domain/$foldername/reports/$subdomain.html
  nmap -sV -T3 -Pn -p2075,2076,6443,3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,7447,7080,8880,8983,5673,7443,19000,19080 $subdomain >> ./$domain/$foldername/reports/$subdomain.html
  echo "</pre>">> ./$domain/$foldername/reports/$subdomain.html



  echo "</html>" >> ./$domain/$foldername/reports/$subdomain.html
}
master_report()
{

#this code will generate the html page/domain report for target
  echo '<html>
<head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">' >> ./$domain/$foldername/master_report.html
echo "<title>Recon Report for $domain</title>
<style>
code[class*=language-],pre[class*=language-]{color:#000;background:0 0;text-shadow:0 1px #fff;font-family:'Inconsolata', monospace;text-align:left;white-space:pre;word-spacing:normal;word-break:break-word;word-wrap:normal;line-height:1.5;-moz-tab-size:4;-o-tab-size:4;tab-size:4;-webkit-hyphens:none;-moz-hyphens:none;-ms-hyphens:none;hyphens:none}code[class*=language-] ::-moz-selection,code[class*=language-]::-moz-selection,pre[class*=language-] ::-moz-selection,pre[class*=language-]::-moz-selection{text-shadow:none;background:#b3d4fc}code[class*=language-] ::selection,code[class*=language-]::selection,pre[class*=language-] ::selection,pre[class*=language-]::selection{text-shadow:none;background:#b3d4fc}@media print{code[class*=language-],pre[class*=language-]{text-shadow:none}}pre[class*=language-]{padding:1em;margin:.5em 0;overflow:auto}:not(pre)>code[class*=language-],pre[class*=language-]{background:#f5f2f0}:not(pre)>code[class*=language-]{padding:.1em;border-radius:.3em;white-space:normal}.token.cdata,.token.comment,.token.doctype,.token.prolog{color:#708090}.token.punctuation{color:#999}.namespace{opacity:.7}.token.boolean,.token.constant,.token.deleted,.token.number,.token.property,.token.symbol,.token.tag{color:#905}.token.attr-name,.token.builtin,.token.char,.token.inserted,.token.selector,.token.string{color:#690}.language-css .token.string,.style .token.string,.token.entity,.token.operator,.token.url{color:#a67f59;background:hsla(0,0%,100%,.5)}.token.atrule,.token.attr-value,.token.keyword{color:#07a}.token.function{color:#DD4A68}.token.important,.token.regex,.token.variable{color:#0dee00}.token.bold,.token.important{font-weight:700}.token.italic{font-style:italic}.token.entity{cursor:help}
</style><style>
code,kbd,pre,samp{font-family:Inconsolata,monospace}button,hr,input{overflow:visible}audio,canvas,progress,sub,sup{vertical-align:baseline}[type=checkbox],[type=radio],legend{padding:0;box-sizing:border-box}ol,pre,ul{margin:0 0 20px}.hljs,pre{overflow-x:auto}.hljs,article,aside,blockquote p,details,figcaption,figure,footer,header,img,main,menu,nav,section{display:block}#wrapper:after,.blog-description:after,.clearfix:after,.post-date:after{content:""}.container,.post-stub,sub,sup{position:relative}html{line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}h1{margin:.67em 0}h1,h2,h3,h4,h5,h6{margin-bottom:20px}figure{margin:1em 40px}a{background-color:transparent;-webkit-text-decoration-skip:objects;text-decoration:none}abbr[title]{border-bottom:none;text-decoration:underline;text-decoration:underline dotted}b,strong{font-weight:bolder}.container,table{width:100%}svg:not(:root){overflow:hidden}button,input,optgroup,select,textarea{font-family:Raleway,monospace;font-size:100%;line-height:1.15;margin:0}.footer,.site-header,textarea{overflow:auto}button,select{text-transform:none}.page-title,.post-header,.post-stub-tag,.post-stub-title,.post-title,.site-header,.site-title,h1,h2,h3,h4,h5,h6{text-transform:uppercase}fieldset{padding:.35em .75em .625em}ol,p,ul{line-height:1.5em}pre,table td{padding:10px}h2,h3{padding-top:40px;font-weight:900}a,a code{color:#00a0fc}body,html{height:100%}body{margin:0;background:#fefefe;color:#424242;font-family:Raleway,-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,Oxygen,Ubuntu,\"Helvetica Neue\",Arial,sans-serif;font-size:24px}h1{font-size:35px}h2{font-size:28px}h3{font-size:26px}h4{font-size:24px;margin-bottom:18px}h5{font-size:16px;margin-bottom:15px}h6{font-size:14px;margin-bottom:12px}p{margin:0 0 30px}ol ol,ol ul,ul ol,ul ul{margin:10px 10px 12px 20px}ol li,ul li{margin:0 0 2px}ol li:last-of-type,ul li:last-of-type{margin-bottom:0}blockquote{border-left:1px dotted #00a0fc;margin:40px 0;padding:5px 30px}blockquote p{color:#aeadad;font-style:italic;margin:0;width:100%}pre{background:#f1f0ea;border:1px solid #dddbcc;border-radius:3px;font-size:16px}pre code{padding:0}code{padding:2px 4px;font-size:100%;color:#444;background-color:#f1f0ea;border-radius:4px}.row{display:flex}.column{flex:100%}hr{box-sizing:content-box;height:0;border:none;border-bottom:1px solid #333;margin:45px 0}table tbody>tr:nth-child(odd)>td,table tbody>tr:nth-child(odd)>th{background-color:#f7f7f3}table th{padding:0 10px 10px;text-align:left}.center,.error,.footer-copyright,.page-title,.post-header,.post-title,.share,.share a,.site-header{text-align:center}table tr{border-bottom:1px dotted #aeadad}::selection{background:#fff5b8;color:#000;display:block}::-moz-selection{background:#fff5b8;color:#000;display:block}.hidden{text-indent:-9999px;visibility:hidden;display:none}.clearfix:after{display:table;clear:both}.container{max-width:100%}.containerleft{max-width:500px}.containerright{width:10%}#wrapper{height:auto;min-height:100%;margin-bottom:-265px}#wrapper:after{display:block;height:265px}.comments{margin-top:10px}.site-header{padding:40px 0 0}.site-title-wrapper{display:table;margin:0 auto}.site-title{float:left;font-size:14px;font-weight:600;margin:0}.site-title a{float:left;background:#00a0fc;color:#fefefe;padding:5px 10px 6px}.site-nav-item a:hover{color:#424242}#latest-post{display:none}.post-container-left{width:49%;float:left;margin:auto}.post-container-right{width:49%;float:right;margin:auto}.post-header{border-bottom:1px solid #333;margin:0 0 50px;padding:0}.page-title,.post-title{font-size:55px;font-weight:900;margin:15px 0}.page-title{margin:15px 40px}.blog-description,.post-date{color:#aeadad;font-size:14px;font-weight:600;line-height:1;margin:25px 0 0;text-align:center}.single-post-container{margin-top:50px;padding-left:15px;padding-right:15px;box-sizing:border-box}body.dark aside input{border:1px solid #333}body.dark,body.dark input{background-color:#1e2227;color:#fff}body.dark .home-section-col ul li a,body.dark .home-section-col ul li:nth-child(even),body.dark .post-stub a,body.dark aside ul li a{color:#fff}body.dark .post-stub:hover,body.dark :not(pre)>code[class*=language-],body.dark pre,body.dark pre[class*=language-]{background:#282c34}body.dark code[class*=language-],body.dark pre[class*=language-]{text-shadow:none;color:#fff}body.dark .language-css .token.string,body.dark .style .token.string,body.dark .token.entity,body.dark .token.operator,body.dark .token.url{background:0 0}body.dark table tbody>tr:nth-child(odd)>td,body.dark table tbody>tr:nth-child(odd)>th{background:#282c34}body.dark .token.attr-name,body.dark .token.builtin,body.dark .token.char,body.dark .token.inserted,body.dark .token.selector,body.dark .token.string{color:#ecdb54}
</style>
<script>
document.addEventListener('DOMContentLoaded', (event) => {
  ((localStorage.getItem('mode') || 'dark') === 'dark') ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')
})
</script></head>" >> ./$domain/$foldername/master_report.html




echo '<body class="dark"><header class="site-header">
<div class="site-title"><p>' >> ./$domain/$foldername/master_report.html
echo "<a style=\"cursor: pointer\" onclick=\"localStorage.setItem('mode', (localStorage.getItem('mode') || 'dark') === 'dark' ? 'bright' : 'dark'); localStorage.getItem('mode') === 'dark' ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')\" title=\"Switch to light or dark theme\">🌓 Light|dark mode</a>

</p>
</div>
</header>" >> ./$domain/$foldername/master_report.html


 echo '<div id="wrapper"><div id="container">' >> ./$domain/$foldername/master_report.html
echo "<h1 class=\"post-title\" itemprop=\"name headline\">Recon Report for <a href=\"http://$domain\">$domain</a></h1>" >> ./$domain/$foldername/master_report.html
echo "<p class=\"blog-description\">Generated by LazyRecon on $(date) </p>" >> ./$domain/$foldername/master_report.html
echo '<div class="container single-post-container">
<article class="post-container-left" itemscope="" itemtype="http://schema.org/BlogPosting">
<header class="post-header">
</header>
<div class="post-content clearfix" itemprop="articleBody">
<h2>Total scanned subdomains</h2>
<table>
<tbody><tr>
 <th>Subdomains</th>
 <th>Scanned Urls</th>
 </tr>' >> ./$domain/$foldername/master_report.html

 #we just created the first part of the page now we just iterate through our scanned subdomains then we count number of found content from dirsearch directory
 #all of this should be formatted inside table

cat ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt | while read nline; do
echo "<tr>
 <td><a href='./reports/$nline.html'>$nline</a></td>
 <td>$(wc -l ~/tools/dirsearch/reports/$nline/* | awk '{print $1}')</td>
 </tr>" >> ./$domain/$foldername/master_report.html
done
echo "</tbody></table>
<div><h2>Possible NS Takeovers</h2></div>
<pre>" >> ./$domain/$foldername/master_report.html
cat ./$domain/$foldername/pos.txt >> ./$domain/$foldername/master_report.html
echo "</pre></div>" >> ./$domain/$foldername/master_report.html


echo '</article><article class="post-container-right" itemscope="" itemtype="http://schema.org/BlogPosting">
<header class="post-header">

</header>

<div class="post-content clearfix" itemprop="articleBody">
<h2>IP Address space</h2>
<pre>' >> ./$domain/$foldername/master_report.html
cat ./$domain/$foldername/ipaddress.txt >> ./$domain/$foldername/master_report.html
echo "</pre>
<h2>Dig Info</h2>
<pre>
$(dig $line)
</pre>" >> ./$domain/$foldername/master_report.html
echo "<h2>Host Info</h2>
<pre>
$(host $domain)
</pre>" >> ./$domain/$foldername/master_report.html
echo "<h2>Response Headers</h2>
<pre>
$(curl -sSL -D - $domain  -o /dev/null)
</pre>" >> ./$domain/$foldername/master_report.html
echo "<h2>NMAP Results</h2>
<pre>
$(nmap -sV -T3 -Pn -p3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,7447,7080,8880,8983,5673,7443,19000,19080 $domain)
</pre>
</div></article></div>
</div></div></body></html>" >> ./$domain/$foldername/master_report.html


}

logo(){
  #can't have a bash script without a cool logo :D
  echo "${red}

 _     ____  ____ ___  _ ____  _____ ____  ____  _
/ \   /  _ \/_   \\\  \///  __\/  __//   _\/  _ \/ \  /|
| |   | / \| /   / \  / |  \/||  \  |  /  | / \|| |\ ||
| |_/\| |-||/   /_ / /  |    /|  /_ |  \__| \_/|| | \||
\____/\_/ \|\____//_/   \_/\_\\\____\\\____/\____/\_/  \\|

${reset}                                                      "
}
cleantemp(){

    rm ./$domain/$foldername/temp.txt
    rm ./$domain/$foldername/domaintemp.txt
    rm ./$domain/$foldername/cleantemp.txt
}
main(){
  clear
  logo

  if [ -d "./$domain" ]
  then
    echo "This is a known target."
  else
    mkdir ./$domain
  fi

  mkdir ./$domain/$foldername
  mkdir ./$domain/$foldername/reports/
  mkdir ./$domain/$foldername/screenshots/
  mkdir ./$domain/$foldername/content/
  touch ./$domain/$foldername/crtsh.txt
  touch ./$domain/$foldername/mass.txt
  touch ./$domain/$foldername/cnames.txt
  touch ./$domain/$foldername/pos.txt
  touch ./$domain/$foldername/alldomains.txt
  touch ./$domain/$foldername/temp.txt
  touch ./$domain/$foldername/domaintemp.txt
  touch ./$domain/$foldername/ipaddress.txt
  touch ./$domain/$foldername/cleantemp.txt
  touch ./$domain/$foldername/unreachable.html
  touch ./$domain/$foldername/responsive-$(date +"%Y-%m-%d").txt
  touch ./$domain/$foldername/responsive-$(date +"%Y-%m-%d")-codes.txt

  touch ./$domain/$foldername/master_report.html
  rm -rf ~/tools/dirsearch/reports/*.$domain
  recon $domain
  master_report $domain
  echo "${green}Scan for $domain finished successfully${reset}"
  cleantemp $domain
}

path=$(pwd)
foldername=recon-$(date +"%Y-%m-%d")
main $domain

