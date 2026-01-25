"""
ASN to abuse email mapping database.

Maps Autonomous System Numbers (ASN) to their corresponding abuse contact emails.
EPIC-005: Normalized to lists for multi-contact handling.
"""

# Enhanced ASN to abuse email mapping
ASN_ABUSE_EMAIL_DB = {
    # Major Cloud Providers
    "16509": ["abuse@amazon.com", "ec2-abuse@amazon.com"],  # Amazon AWS
    "14618": ["abuse@amazon.com"],  # Amazon AWS
    "8075": ["abuse@microsoft.com", "msrc@microsoft.com"],  # Microsoft Azure
    "15169": ["abuse@google.com"],  # Google Cloud
    "13335": ["abuse@cloudflare.com", "trust-safety@cloudflare.com"],  # Cloudflare
    "20940": ["abuse@akamai.com"],  # Akamai
    # Major Hosting Providers
    "14061": ["abuse@digitalocean.com"],  # DigitalOcean
    "16276": ["abuse@ovh.com"],  # OVH
    "24940": ["abuse@hetzner.de"],  # Hetzner
    "63949": ["abuse@linode.com"],  # Linode
    "62240": ["abuse@vultr.com"],  # Vultr
    "36351": ["abuse@godaddy.com"],  # GoDaddy
    "26496": ["abuse@godaddy.com"],  # GoDaddy
    "46606": ["abuse@unified-layer.com"],  # Unified Layer (Bluehost, HostGator)
    "46562": ["abuse@totaluptime.com"],  # Total Uptime
    "19318": ["abuse@interserver.net"],  # Interserver
    "55286": ["abuse@server.lu"],  # Server.lu
    "49505": ["abuse@selectel.ru"],  # Selectel
    "39561": ["abuse@contabo.com"],  # Contabo
    "51167": ["abuse@contabo.com"],  # Contabo
    "8560": ["abuse@oneandone.net"],  # IONOS (1&1)
    "29066": ["abuse@velianet.com"],  # Velia.net
    "47583": ["abuse@hostinger.com"],  # Hostinger
    "20473": ["abuse@vultr.com"],  # Vultr (The Constant Company)
    "62567": ["abuse@digitalocean.com"],  # DigitalOcean NY2
    # European Providers
    "12876": ["abuse@online.net"],  # Online.net (Scaleway)
    "12322": ["abuse@proxad.net"],  # Free/Proxad
    "3215": ["abuse@orange.com"],  # Orange
    "5432": ["abuse@proximus.be"],  # Proximus
    "6830": ["abuse@upc.ch"],  # UPC
    "6739": ["abuse@ono.com"],  # ONO
    "3352": ["abuse@telefonica.es"],  # Telefonica
    # US Providers
    "7922": ["abuse@comcast.net"],  # Comcast
    "20115": ["abuse@charter.com"],  # Charter/Spectrum
    "22773": ["abuse@cox.net"],  # Cox
    "11427": ["abuse@twc.com"],  # Time Warner
    "7018": ["abuse@att.net"],  # AT&T
    "701": ["abuse@verizon.net"],  # Verizon
    "22612": ["abuse@namecheap.com"],  # Namecheap
    "26347": ["abuse@dreamhost.com"],  # DreamHost
    "199524": ["abuse@gcorelabs.com"],  # G-Core Labs
    "32244": ["abuse@liquidweb.com"],  # Liquid Web
    "35916": ["abuse@multacom.com"],  # Multacom Corporation
    "51747": ["abuse@internetvikings.com"],  # Internet Vikings
    # More Hosting Providers
    "32613": ["abuse@iweb.com"],  # iWeb
    "54825": ["abuse@packet.com"],  # Packet (Equinix Metal)
    "21859": ["abuse@zenlayer.com"],  # Zenlayer
    "40676": ["abuse@psychz.net"],  # Psychz Networks
    "32780": ["abuse@hostwinds.com"],  # HostWinds
    "29802": ["abuse@hivelocity.net"],  # Hivelocity
    # Additional Cloud & Hosting Providers
    "13448": ["abuse@force3.com"],  # Force3
    "36236": ["abuse@netactivity.us"],  # NetActuate
    "50673": ["abuse@serverius.net"],  # Serverius
    "20738": ["abuse@dedipath.com"],  # DediPath
    "136168": ["abuse@cloudie.hk"],  # Cloudie Limited
    "149018": ["abuse@scaleup.com", "security@scaleup.com"],  # ScaleUp Technologies
    "202422": ["abuse@gcorelabs.com"],  # G-Core Labs Luxembourg
    "42831": ["abuse@ukfast.co.uk"],  # UKFast
    "49453": ["abuse@as-zone.org"],  # Global Layer B.V.
    "57043": ["abuse@hostkey.com"],  # HostKey B.V.
    "206264": ["abuse@amarutu.com"],  # Amarutu Technology Ltd
    "212238": ["abuse@cdnext.com"],  # Datacamp Limited
    "24961": ["abuse@myloc.de"],  # MyLoc Managed IT AG
    # More European Providers
    "201011": ["abuse@core-backbone.com"],  # Core-Backbone GmbH
    "50300": ["abuse@custdc.com"],  # CustodianDC Limited
    "9009": ["abuse@m247.ro"],  # M247 Europe SRL
    "61317": ["abuse@der.net"],  # Digital Energy Technologies Chile SpA
    "16265": ["abuse@leaseweb.com"],  # Leaseweb
    "60781": ["abuse@leaseweb.com"],  # LeaseWeb Netherlands
    # Latin American Providers
    "27699": ["abuse@telecom.com.ar"],  # Telecom Argentina
    "7738": ["abuse@telecom.com.br"],  # Telecom Brasil
    "28573": ["abuse@claro.com.co"],  # Claro Colombia
    "19429": ["abuse@emcali.net.co"],  # Emcali Colombia
    "14080": ["abuse@une.net.co"],  # UNE Colombia
    "52257": ["abuse@cnnet.com.br"],  # CNNet Brasil
    "61568": ["abuse@fsdata.com.br", "security@fsdata.com.br"],  # FSDATA Brasil
    "28186": ["abuse@iq.com.br"],  # IQ Brasil
    "53062": ["abuse@mundivox.com"],  # Mundivox México
    "8151": ["abuse@uninet.net.mx"],  # Uninet México
    # Asian Providers
    "9808": ["abuse@guangdong.chinamobile.com"],  # China Mobile
    "4134": ["abuse@chinatelecom.cn"],  # China Telecom
    "4837": ["abuse@chinaunicom.cn"],  # China Unicom
    "9583": ["abuse@sify.com"],  # Sify (India)
    "45609": ["abuse@bharti.in"],  # Bharti Airtel
    "17557": ["abuse@ntt.com", "security@ntt.com"],  # NTT Communications
    "2497": ["abuse@iij.ad.jp"],  # Internet Initiative Japan
    "4766": ["abuse@kixs.or.kr"],  # Korea Telecom
    "17676": ["abuse@softbank.jp"],  # SoftBank
    "9318": ["abuse@hanaro.com"],  # SK Broadband Korea
    "7545": ["abuse@tpg.com.au"],  # TPG Australia
    "1221": ["abuse@telstra.com.au"],  # Telstra Australia
    "24516": ["abuse@virtuozzo.com"],  # Virtuozzo (Russia)
    "43317": ["abuse@fish.com"],  # Fish.com
    "62904": ["abuse@eonix.net"],  # Eonix Corporation
    # African & Middle East Providers
    "36998": ["abuse@datacom.co.ug"],  # DataCom Uganda
    "37105": ["abuse@kenpoly.ac.ke"],  # Kenya Polytechnic
    "36994": ["abuse@zuku.co.ke"],  # Zuku Kenya
    "29571": ["abuse@du.ae"],  # Emirates Integrated Telecom
    "15802": ["abuse@du.ae"],  # DU UAE
    # Australian/Oceania Providers
    "4826": ["abuse@vocus.com.au"],  # Vocus Communications
    # Other Notable Providers
    "200019": ["abuse@alexhost.com"],  # Alexhost
    "49981": ["abuse@worldstream.nl"],  # WorldStream
    "60068": ["abuse@cdn77.com"],  # CDN77
    "13414": ["abuse@twitter.com"],  # Twitter
    "32934": ["abuse@facebook.com"],  # Meta/Facebook
    "714": ["abuse@apple.com"],  # Apple
    "36459": ["abuse@github.com"],  # GitHub
}
