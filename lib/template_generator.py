"""
Functions for generating CSV templates for application and URL category management.

This module provides functionality to:

- Generate CSV templates for APP and URL categories from PAN-OS devices
- Retrieve all predefined application subcategories available on the device
- Fetch URL category descriptions from Palo Alto Networks knowledge base
- Normalize category names for consistent formatting
- Suggest default actions for each category (manage, allow, deny)
- Propose associated AD/Local user group names for managed categories
- Create standardized templates for business requirements documentation
"""

import xml.etree.ElementTree as ET

import panos.predefined
import os.path
import csv
import pan.xapi
import sys
from rich import print
import requests
from bs4 import BeautifulSoup
from lib.rich_output import console


import settings


def normalize_category_name(category_name):
    """
    Normalizes the category name by replacing dashes with spaces and converting to lowercase.

    :param category_name (str): The category name to normalize.
    :return: str: The normalized category name.
    """
    # Replace dashes with spaces and convert to lowercase
    normalized = category_name.replace('-', ' ').lower()
    # Remove asterisks
    normalized = normalized.replace('*', '')

    return normalized


def get_url_category_descriptions(palo_kb_url, categories):
    """

    :param palo_kb_url: Link to Palo Alto KB that contains the full list of URL categories and their descriptions
    :param categories: list of URL categories
    :return: list of dictionaries where each entry contains a category name and its description
    """
    # Fetch the HTML content from the URL
    response = requests.get(palo_kb_url)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find the specific table with the given attributes
    table = soup.find('table', attrs={'dir': 'ltr', 'border': '1', 'cellpadding': '0', 'cellspacing': '0'})

    # Normalize the categories for comparison
    normalized_categories = [normalize_category_name(cat) for cat in categories]

    # Extract all rows from the table
    rows = table.find_all('tr') if table else []

    # Prepare a list to hold category descriptions
    category_descriptions = []

    # Iterate over each row to find matching categories
    for row in rows:
        columns = row.find_all('td')
        if len(columns) >= 2:
            category_name = columns[0].get_text(strip=True)
            normalized_category_name = normalize_category_name(category_name)

            # Check if the normalized category name is in the user-provided list
            if normalized_category_name in normalized_categories:
                description = columns[1].get_text(strip=True)
                original_category_name = categories[normalized_categories.index(normalized_category_name)]
                category_descriptions.append({
                    'category': original_category_name,
                    'description': description
                })

    return category_descriptions


def generate_app_categories_template(panos_device):
    """
    Generates an application categories template for a PAN-OS device. This template includes all predefined
    application subcategories available on the device.

    Args:
        panos_device: The PAN-OS device to connect to for retrieving predefined applications.

    Returns:
        A list of all APP category names currently known to the PAN-OS device
    """
    if os.path.exists(settings.APP_CATEGORIES_TEMPLATE_FILENAME):
        if settings.DEBUG_OUTPUT: print(f"App categories template file already exists - bypassing its creation...")
        # retrieving all current application subcategories from the device to make sure that all of them are covered in the Requirements
        with console.status('Retrieving all predefined applications to establish all available application sub-categories...', spinner='dots') as status:
            # we could get categories using the method in the comment below
            # however it will also include categories available only with App-ID Cloud Engine (ACE) feature
            # that the device must have a license for. If you have this license this method will work quicker than the m
            # one used in this script below this comment section.
            #
            # result = panos_device.op('show predefined xpath "/predefined/application-type"', cmd_xml=True)
            #
            # subcategories = {
            #     entry.get("name")
            #     for subcat in result.iter("subcategory")
            #     for entry in subcat.findall("entry")
            #     if entry.get("name")
            # }
            # list_of_app_categories = sorted(subcategories)

            built_in_apps = panos.predefined.Predefined(panos_device)
            try:
                built_in_apps.refreshall_applications()
            except pan.xapi.PanXapiError as e:
                console.print("[bold red]ERROR:[/bold red] Failed to connect to the PAN-OS device")
                console.print(e)
                sys.exit()
            list_of_app_categories = list()
            for each_app in built_in_apps.application_objects:
                app_meta = built_in_apps.application(each_app, refresh_if_none=True, include_containers=False)
                if app_meta.subcategory is not None:
                    list_of_app_categories.append(app_meta.subcategory)
            list_of_app_categories = list(dict.fromkeys(list_of_app_categories))
            list_of_app_categories.sort()

        console.print(f'Retrieving all predefined applications to establish all available application sub-categories...'
                      f'[green]✓[/green] complete ([bold]{len(list_of_app_categories)}[/bold] categories found)')

    else:
        console.print(f"App categories template file does not exist - creating from scratch...")
        built_in_apps = panos.predefined.Predefined(panos_device)
        with console.status('\tRetrieving all predefined applications to establish all available application sub-categories...', spinner='dots') as status:
            built_in_apps.refreshall_applications()
            list_of_app_categories = list()
            for each_app in built_in_apps.application_objects:
                app_meta = built_in_apps.application(each_app, refresh_if_none=True, include_containers=False)
                if app_meta.subcategory is not None:
                    list_of_app_categories.append(app_meta.subcategory)
            list_of_app_categories = list(dict.fromkeys(list_of_app_categories))
            list_of_app_categories.sort()
        console.print('[green][/green]')

        # Initialise CSV file for app categories template
        f_app_categories_template = open(settings.APP_CATEGORIES_TEMPLATE_FILENAME, 'w', newline='')
        writer_app_categories_template = csv.writer(f_app_categories_template)
        writer_app_categories_template.writerow(["Category", "Action", "UserID", "Description"])
        # TODO: add a look up for a category description in statically defined dictionary of app categories
        # Write all categories to a file
        for each_category in list_of_app_categories:
            writer_app_categories_template.writerow([each_category, 'alert', "known-user", 'not available yet'])
        f_app_categories_template.flush()

        print(f"App categories template file (`{settings.APP_CATEGORIES_TEMPLATE_FILENAME}`) has been created.\n"
              f"Now you can clone it having removed the `template_` prefix, update the actions and AD group names "
              f"as required, and then re-run this script")

    return list_of_app_categories


def generate_url_categories_template(panos_device):
    """
    Checks if a URL categories template file exists and either skips creation if found or creates a new one from a
    predefined list of URL categories.

    The function first verifies the existence of a URL categories template file defined in settings. If the file exists,
    it logs a message indicating that the file already exists and bypasses its creation. Otherwise, it logs a message
    stating that the file does not exist and proceeds to create the file from a list of predefined URL categories.
    Each URL category includes multiple attributes such as category name, action type, user type, and a description.

    Attributes for each URL category:
    - Name: The name of the URL category.
    - Action: Defines the action type (e.g., "alert", "manage", "deny") for the URL category.
    - User: Specifies the user type (e.g., "known-user", "any").
    - Alias: An alias or alternative name for the URL category.
    - Description: A detailed description of what the URL category encompasses.

    Args:
        panos_device: The PAN-OS device from which predefined URL categories are retrieved.

    Returns:
        A list of all URL category names currently known to the PAN-OS device
    """
    # retrieving all current palo_kb_url categories from the device to make sure that all of them are covered in the Requirements
    try:
        with console.status('Retrieving all predefined URL-categories...', spinner='dots') as status:
            built_in_url_categories_xml_string = panos_device.op('show predefined xpath "/predefined/pan-url-categories"', xml=True)
            built_in_url_categories_xml = ET.fromstring(built_in_url_categories_xml_string)

            # Extract names from 'entry' elements
            list_of_built_in_url_categories = [entry.get('name') for entry in built_in_url_categories_xml.findall(".//entry")]
            list_of_built_in_url_categories.sort()
        console.print(f'Retrieving all predefined URL-categories...[green]✓[/green] complete ([bold]{len(list_of_built_in_url_categories)-3}[/bold] categories found)')
        # (we subtract 3 risk categories because they should not be counted for cross-referencing with requirements)

        if os.path.exists(settings.URL_CATEGORIES_TEMPLATE_FILENAME):
            if settings.VERBOSE_OUTPUT:
                console.print(f"URL categories template file already exists - bypassing its creation...")
        else:
            console.print(f"URL categories template file does not exist - creating from scratch...")
            list_of_url_categories = [
                {"category": "abortion",                                "action": "alert",      "user_type": "known-user",  "label": "abortion",                "description": "Sites that pertain to information or groups in favor of or against abortion, details regarding abortion procedures, help or support forums for or against abortion, or sites that provide information regarding the consequences/effects of pursuing (or not) an abortion."},
                {"category": "abused-drugs",                            "action": "manage",     "user_type": "known-user",  "label": "abused-drugs",            "description": "Sites that promote the abuse of both legal and illegal drugs, use and sale of drug related paraphernalia, manufacturing and/or selling of drugs."},
                {"category": "adult",                                   "action": "manage",     "user_type": "known-user",  "label": "adult",                   "description": "Sexually explicit material, media (including language), art, and/or products, online groups or forums that are sexually explicit in nature. Sites that promote adult services such as video/telephone conferencing, escort services, strip clubs, etc. Anything containing adult content (even if it's games or comics) will be categorized as adult."},
                {"category": "alcohol-and-tobacco",                     "action": "alert",      "user_type": "known-user",  "label": "alcohol-and-tobacco",     "description": "Sites that pertain to the sale, manufacturing, or use of alcohol and/or tobacco products and related paraphernalia. Includes sites related to electronic cigarettes."},
                {"category": "artificial-intelligence",                 "action": "alert",      "user_type": "known-user",  "label": "ai",                      "description": "Websites that use machine learning and deep learning models, including large language models, to provide services that would have typically required human intelligence. The services provided include but are not limited to chatbot, productivity, summarizer, transcriber, no-code, and audio or video editing-related services. Emphasis is given to websites hosting the actual AI service, not informational AI content."},
                {"category": "auctions",                                "action": "alert",      "user_type": "known-user",  "label": "auctions",                "description": "Sites that promote the sale of goods between individuals."},
                {"category": "business-and-economy",                    "action": "alert",      "user_type": "known-user",  "label": "business-and-economy",    "description": "Marketing, management, economics, and sites relating to entrepreneurship or running a business. Includes advertising and marketing firms. Should not include corporate websites as they should be categorized with their technology. Also shipping sites, such as fedex.com and ups.com."},
                {"category": "command-and-control",                     "action": "deny",       "user_type": "any",         "label": "command-and-control",     "description": "Command-and-control URLs and domains used by malware and/or compromised systems to surreptitiously communicate with an attacker's remote server to receive malicious commands or exfiltrate data"},
                {"category": "computer-and-internet-info",              "action": "alert",      "user_type": "known-user",  "label": "computer-and-internet",   "description": "General information regarding computers and the internet. Should include sites about computer science, engineering, hardware, software, security, programming, etc. Programming may have some overlap with reference, but the main category should remain computer and internet info."},
                {"category": "content-delivery-networks",               "action": "alert",      "user_type": "known-user",  "label": "content-delivery",        "description": "Sites whose primary focus is delivering content to 3rd parties such as advertisements, media, files, etc. Also includes image servers."},
                {"category": "copyright-infringement",                  "action": "manage",     "user_type": "known-user",  "label": "copyright-breach",        "description": "Domains with illegal content, such as content that alerts illegal download of software or other intellectual property, which poses a potential liability risk. This category was introduced to enable adherence to child protection laws required in the education industry as well as laws in countries that require internet providers to prevent users from sharing copyrighted material through their service."},
                {"category": "cryptocurrency",                          "action": "manage",     "user_type": "known-user",  "label": "cryptocurrency",          "description": "Websites that promote cryptocurrencies, crypto mining websites (but not embedded crypto miners), cryptocurrency exchanges and vendors, and websites that manage cryptocurrency wallets and ledgers. This category does not include traditional financial services websites that reference cryptocurrencies, websites that explain and describe how cryptocurrencies and blockchains work, or websites that contain embedded crypto currency miners (grayware)."},
                {"category": "dating",                                  "action": "manage",     "user_type": "known-user",  "label": "dating",                  "description": "Websites offering online dating services, advice, and other personal ads"},
                {"category": "dynamic-dns",                             "action": "manage",     "user_type": "known-user",  "label": "dynamic-dns",             "description": "Hosts and domain names for systems with dynamically assigned IP addresses and which are oftentimes used to deliver malware payloads or C2 traffic. Also, dynamic DNS domains do not go through the same vetting process as domains that are registered by a reputable domain registration company, and are therefore less trustworthy."},
                {"category": "educational-institutions",                "action": "alert",      "user_type": "known-user",  "label": "educational-institute",   "description": "Official websites for schools, colleges, universities, school districts, online classes, and other academic institutions. These refer to larger, established educational institutions such as elementary schools, high schools, universities, etc. Tutoring academies can go here as well."},
                {"category": "entertainment-and-arts",                  "action": "alert",      "user_type": "known-user",  "label": "entertainment-arts",      "description": "Sites for movies, television, radio, videos, programming guides/tools, comics, performing arts, museums, art galleries, or libraries. Includes sites for entertainment, celebrity and industry news."},
                {"category": "extremism",                               "action": "manage",     "user_type": "known-user",  "label": "extremism",               "description": "Websites promoting terrorism, racism, fascism, or other extremist views discriminating against people or groups of different ethnic backgrounds, religions or other beliefs. This category was introduced to enable adherence to child protection laws required in the education industry. In some regions, laws and regulations may prohibit alerting access to extremist sites, and alerting access may pose a liability risk."},
                {"category": "financial-services",                      "action": "alert",      "user_type": "known-user",  "label": "financial-services",      "description": "Websites pertaining to personal financial information or advice, such as online banking, loans, mortgages, debt management, credit card companies, and insurance companies. Does not include sites relating to stock markets, brokerages or trading services.Includes sites for foreign currency exchange. Includes sites for foreign currency exchange."},
                {"category": "gambling",                                "action": "manage",     "user_type": "known-user",  "label": "gambling",                "description": "Lottery or gambling websites that facilitate the exchange of real and/or virtual money. Related websites that provide information, tutorials or advice regarding gambling, including betting odds and pools. Corporate websites for hotels and casinos that do not enable gambling are categorized under Travel."},
                {"category": "games",                                   "action": "manage",     "user_type": "known-user",  "label": "games",                   "description": "Sites that provide online play or download of video and/or computer games, game reviews, tips, or cheats, as well as instructional sites for non-electronic games, sale/trade of board games, or related publications/media."},
                {"category": "government",                              "action": "alert",      "user_type": "known-user",  "label": "government",              "description": "Official websites for local, state, and national governments, as well as related agencies, services, or laws."},
                {"category": "grayware",                                "action": "deny",       "user_type": "any",         "label": "grayware",                "description": "Web content that does not pose a direct security threat but that display other obtrusive behavior and tempt the end user to grant remote access or perform other unauthorized actions. Grayware includes illegal activities, criminal activities, rogueware, adware, and other unwanted or unsolicited applications, such as embedded crypto miners, clickjacking or hijackers that change the elements of the browser. Typosquatting domains that do not exhibit maliciousness and are not owned by the targeted domain will be categorized as grayware."},
                {"category": "hacking",                                 "action": "deny",       "user_type": "any",         "label": "hacking",                 "description": "Sites relating to the illegal or questionable access to or the use of communications equipment/software. Development and distribution of programs, how-to-advice and/or tips that may result in the compromise of networks and systems. Also includes sites that facilitate the bypass of licensing and digital rights systems."},
                {"category": "health-and-medicine",                     "action": "alert",      "user_type": "known-user",  "label": "health-and-medicine",     "description": "Sites containing information regarding general health information, issues, and traditional and non-traditional tips, remedies, and treatments. Also includes sites for various medical specialties, practices and facilities (such as gyms and fitness clubs) as well as professionals. Sites relating to medical insurance and cosmetic surgery are also included."},
                {"category": "home-and-garden",                         "action": "alert",      "user_type": "known-user",  "label": "home-and-garden",         "description": "Information, products, and services regarding home repair and maintenance, architecture, design, construction, décor, and gardening."},
                {"category": "hunting-and-fishing",                     "action": "alert",      "user_type": "known-user",  "label": "hunting-and-fishing",     "description": "Hunting and fishing tips, instructions, sale of related equipment and paraphernalia."},
                {"category": "insufficient-content",                    "action": "alert",      "user_type": "known-user",  "label": "insufficient-content",    "description": "Websites and services that present test pages, no content, provide API access not intended for end-user display or require authentication without displaying any other content suggesting a different categorization. Should not include websites providing remote access, such as web based VPN solutions, web based email services or identified credential phishing pages."},
                {"category": "internet-communications-and-telephony",   "action": "manage",     "user_type": "known-user",  "label": "inet-comms-telephony",    "description": "Sites that support or provide services for video chatting, instant messaging, or telephony capabilities."},
                {"category": "internet-portals",                        "action": "alert",      "user_type": "known-user",  "label": "internet-portals",        "description": "Sites that serve as a starting point for users, usually by aggregating a broad set of content and topics."},
                {"category": "job-search",                              "action": "alert",      "user_type": "known-user",  "label": "job-search",              "description": "Sites that provide job listings and employer reviews, interview advice and tips, or related services for both employers and prospective candidates."},
                {"category": "legal",                                   "action": "alert",      "user_type": "known-user",  "label": "legal",                   "description": "Information, analysis or advice regarding the law, legal services, legal firms, or other legal related issues."},
                {"category": "malware",                                 "action": "deny",       "user_type": "any",         "label": "malware",                 "description": "Sites known to host malware or used for command and control (C2) traffic. May also exhibit Exploit Kits."},
                {"category": "military",                                "action": "alert",      "user_type": "known-user",  "label": "military",                "description": "Information or commentary regarding military branches, recruitment, current or past operations, or any related paraphernalia."},
                {"category": "motor-vehicles",                          "action": "alert",      "user_type": "known-user",  "label": "motor-vehicles",          "description": "Information relating to reviews, sales and trading, modifications, parts, and other related discussions for automobiles, motorcycles, boats, trucks and RVs."},
                {"category": "music",                                   "action": "alert",      "user_type": "known-user",  "label": "music",                   "description": "Music sales, distribution, or information. Includes websites for music artists, groups, labels, events, lyrics, and other information regarding the music business. Does not include streaming music."},
                {"category": "newly-registered-domain",                 "action": "manage",     "user_type": "known-user",  "label": "newly-registered-dom",    "description": "Newly registered domains are often generated purposely or by domain generation algorithms and used for malicious activity."},
                {"category": "news",                                    "action": "alert",      "user_type": "known-user",  "label": "news",                    "description": "Online publications, newswire services, and other websites that aggregate current events, weather, or other contemporary issues. Includes newspapers, radio stations, magazines, and podcasts."},
                {"category": "not-resolved",                            "action": "alert",      "user_type": "known-user",  "label": "not-resolved",            "description": "Indicates that the website was not found in the local URL filtering database and the firewall was unable to connect to the cloud database to check the category. When a URL category lookup is performed, the firewall first checks the dataplane cache for the URL, if no match is found, it will then check the management plane cache, and if no match is found there, it queries the URL database in the cloud. When deciding on what action to take for traffic that is categorized as not-resolved, be aware that setting the action to block may be very disruptive to users."},
                {"category": "nudity",                                  "action": "alert",      "user_type": "known-user",  "label": "nudity",                  "description": "Sites that contain nude or seminude depictions of the human body, regardless of context or intent, such as artwork. Includes nudist or naturist sites containing images of participants."},
                {"category": "online-storage-and-backup",               "action": "manage",     "user_type": "known-user",  "label": "online-storage",          "description": "Websites that provide online storage of files for free and as a service."},
                {"category": "parked",                                  "action": "deny",       "user_type": "any",         "label": "parked",                  "description": "Domains registered by individuals, oftentimes later found to be used for credential phishing. These domains may be similar to legitimate domains, for example, pal0alto0netw0rks.com, with the intent of phishing for credentials or personal identify information. Or, they may be domains that an individual purchases rights to in hopes that it may be valuable someday, such as panw.net."},
                {"category": "peer-to-peer",                            "action": "managed",    "user_type": "known-user",  "label": "peer-to-peer",            "description": "Sites that provide access to or clients for peer-to-peer sharing of torrents, download programs, media files, or other software applications. This is primarily for those sites that provide bittorrent download capabilities. Does not include shareware or freeware sites."},
                {"category": "personal-sites-and-blogs",                "action": "alert",      "user_type": "known-user",  "label": "personal-sites-blogs",    "description": "Personal websites and blogs by individuals or groups. Should try to first categorize based on content. For example, if someone has a blog just about cars, then the site should be categorized under `motor vehicles`. However, if the site is a pure blog, then it should remain under `personal sites and blogs`."},
                {"category": "philosophy-and-political-advocacy",       "action": "alert",      "user_type": "known-user",  "label": "philosophy-politics",     "description": "Sites containing information, viewpoints or campaigns regarding philosophical or political views."},
                {"category": "phishing",                                "action": "deny",       "user_type": "any",         "label": "phishing",                "description": "Web content that covertly attempts to fool the user in order to harvest information, including login credentials, credit card information – voluntarily or involuntarily, account numbers, PINs, and any information considered to be personally identifiable information (PII) from victims via social engineering techniques.  Technical support scams and scareware is also included as phishing."},
                {"category": "private-ip-addresses",                    "action": "alert",      "user_type": "known-user",  "label": "private-ip-addresses",    "description": "This category includes IP addresses defined in RFC 1918, 'Address Allocation for Private Intranets? It also includes domains not registered with the public DNS system ( *.local and *.onion)."},
                {"category": "proxy-avoidance-and-anonymizers",         "action": "deny",       "user_type": "any",         "label": "proxy-avoidance",         "description": "URLs and services often used to bypass content filtering products."},
                {"category": "questionable",                            "action": "continue",   "user_type": "known-user",  "label": "questionable",            "description": "Websites containing tasteless humor, offensive content targeting specific demographics of individuals or groups of people."},
                {"category": "real-estate",                             "action": "alert",      "user_type": "known-user",  "label": "real-estate",             "description": "Information on property rentals, sales and related tips or information. Includes sites for real estate agents, firms, rental services, listings (and aggregates), and property improvement."},
                {"category": "recreation-and-hobbies",                  "action": "alert",      "user_type": "known-user",  "label": "recreation-hobbies",      "description": "Information, forums, associations, groups, and publications on recreations and hobbies."},
                {"category": "reference-and-research",                  "action": "alert",      "user_type": "known-user",  "label": "reference-research",      "description": "Personal, professional, or academic reference portals, materials, or services. Includes online dictionaries, maps, almanacs, census information, libraries, genealogy and scientific information."},
                {"category": "religion",                                "action": "alert",      "user_type": "known-user",  "label": "religion",                "description": "Information regarding various religions, related activities or events. Includes websites for religious organizations, officials and places of worship.Includes sites for fortune telling."},
                {"category": "remote-access",                           "action": "alert",      "user_type": "known-user",  "label": "remote-access",           "description": "Sites that provide tools or information to facilitate authorized remote access to private computers and attached networks."},
                {"category": "scanning-activity",                       "action": "deny",       "user_type": "known-user",  "label": "scanning-activity",       "description": "Adversaries are increasingly taking advantage of infected hosts to scan a network for vulnerabilities and launch targeted attacks. Additionally, attackers frequently include such probing activities in their malicious campaigns to carry out attacks on a network. Palo Alto Networks defines these scanning and probing tactics as “Scanning Activity” and are considered to be indicators of compromise."},
                {"category": "search-engines",                          "action": "alert",      "user_type": "known-user",  "label": "search-engines",          "description": "Sites that provide a search interface using keywords, phrases, or other parameters that may return information, websites, images or files as results."},
                {"category": "sex-education",                           "action": "alert",      "user_type": "known-user",  "label": "sex-education",           "description": "Information on reproduction, sexual development, safe sex practices, sexually transmitted diseases, birth control, tips for better sex, as well as any related products or related paraphernalia. Includes websites for related groups, forums or organizations."},
                {"category": "shareware-and-freeware",                  "action": "manage",     "user_type": "known-user",  "label": "shareware-freeware",      "description": "Sites that provide access to software, screensavers, icons, wallpapers, utilities, ringtones, themes or widgets for free and/or donations. Also includes open source projects."},
                {"category": "shopping",                                "action": "alert",      "user_type": "known-user",  "label": "shopping",                "description": "Sites that facilitate the purchase of goods and services. Includes online merchants, websites for department stores, retail stores, catalogs, as well as sites that aggregate and monitor prices. Sites listed here should be online merchants that sell a variety of items (or whose main purpose is online sales). A webpage for a cosmetics company that also happens to alert online purchasing should be categorized with cosmetics and not shopping."},
                {"category": "social-networking",                       "action": "manage",     "user_type": "known-user",  "label": "social-networking",       "description": "User communities and sites where users interact with each other, post messages, pictures, or otherwise communicate with groups of people. Does not include blogs or personal sites."},
                {"category": "society",                                 "action": "alert",      "user_type": "known-user",  "label": "society",                 "description": "Topics relating to the general population, issues that impact a large variety of people, such as fashion, beauty, philanthropic groups, societies, or children. Also includes restaurant websites.Includes websites designed for children as well as restaurants."},
                {"category": "sports",                                  "action": "alert",      "user_type": "known-user",  "label": "sports",                  "description": "Information about sporting events, athletes, coaches, officials, teams or organizations, sports scores, schedules and related news, and any related paraphernalia. Includes websites regarding fantasy sports and other virtual sports leagues."},
                {"category": "stock-advice-and-tools",                  "action": "alert",      "user_type": "known-user",  "label": "stock-advice-tools",      "description": "Information regarding the stock market, trading of stocks or options, portfolio management, investment strategies, quotes, or related news."},
                {"category": "streaming-media",                         "action": "manage",     "user_type": "known-user",  "label": "streaming-media",         "description": "Sites that stream audio or video content for free and/or purchase.Includes online radio stations and other streaming music services."},
                {"category": "swimsuits-and-intimate-apparel",          "action": "alert",      "user_type": "known-user",  "label": "intimate-apparel",        "description": "Sites that include information or images concerning swimsuits, intimate apparel or other suggestive clothing."},
                {"category": "training-and-tools",                      "action": "alert",      "user_type": "known-user",  "label": "training-and-tools",      "description": "Sites that provide online education and training and related materials.Can include driving/traffic schools, workplace training, etc."},
                {"category": "translation",                             "action": "alert",      "user_type": "known-user",  "label": "translation",             "description": "Sites that provide translation services, including both user input and URL translations. These sites can also alert users to circumvent filtering as the target page's content is presented within the context of the translator's URL."},
                {"category": "travel",                                  "action": "alert",      "user_type": "known-user",  "label": "travel",                  "description": "Information regarding travel tips, deals, pricing information, destination information, tourism, and related services. Includes websites for hotels, local attractions, casinos, airlines, cruise lines, travel agencies, vehicle rentals and sites that provide booking tools such as price monitors.Includes websites for local points of interest/tourist attractions such as the Eiffel Tower, the Grand Canyon, etc."},
                {"category": "unknown",                                 "action": "alert",      "user_type": "known-user",  "label": "unknown",                 "description": "Sites that have not yet been identified by PAN-DB. If availability is critical to your business and you must alert the traffic, alert on unknown sites, apply the best practice Security profiles to the traffic, and investigate the alerts."},
                {"category": "weapons",                                 "action": "manage",     "user_type": "known-user",  "label": "weapons",                 "description": "Sales, reviews, descriptions of or instructions regarding weapons and their use."},
                {"category": "web-advertisements",                      "action": "alert",      "user_type": "known-user",  "label": "web-advertisements",      "description": "Advertisements, media, content, and banners."},
                {"category": "web-hosting",                             "action": "alert",      "user_type": "known-user",  "label": "web-hosting",             "description": "Free or paid for hosting services for web pages, including information regarding web development, publication, promotion, and other methods to increase traffic."},
                {"category": "web-based-email",                         "action": "manage",     "user_type": "known-user",  "label": "web-based-email",         "description": "Any website that provides access to an email inbox and the ability to send and receive emails."},
                {"category": "real-time-detection",                     "action": "deny",       "user_type": "any",         "label": "real-time-detection",     "description": "Detects New and Unknown Malicious Web-Based Attacks in real-time. This is a feature of Advanced URL Filtering."},
                {"category": "ransomware",                              "action": "deny",       "user_type": "any",         "label": "ransomware",              "description": "Websites known to host ransomware or malicious traffic involved in conducting ransomware campaigns that generally threaten to publish private data or keep access to specific data or systems blocked, usually by encrypting it, until the demanded ransom is paid."},
                {"category": "high-risk",                               "action": "allow",      "user_type": "any",         "label": "high-risk",               "description": "Sites that were previously confirmed to be malicious but have displayed benign activity for at least 30 days. Sites hosted on bulletproof ISPs or using an IP from an ASN that has known malicious content. Sites sharing a domain with a known malicious site. All sites in the “Unknown” category will be high risk."},
                {"category": "medium-risk",                             "action": "allow",      "user_type": "any",         "label": "medium-risk",             "description": "Sites confirmed to be malicious but have displayed benign activity for at least 60 days. All sites in the `Online Storage and Backup` category will be a medium risk by default."},
                {"category": "low-risk",                                "action": "allow",      "user_type": "any",         "label": "low-risk",                "description": "Any site that is not High Risk or Medium Risk. This includes sites that were previously confirmed as malicious but have displayed benign activity for at least 90 days."},
            ]

            # Initialise CSV file for palo_kb_url categories template
            f_url_categories_template = open(settings.URL_CATEGORIES_TEMPLATE_FILENAME, 'w', newline='')
            writer_url_categories_template = csv.writer(f_url_categories_template)
            writer_url_categories_template.writerow(["Category", "Action", "UserID", "Abbreviation", "Description"])
            # Write all categories to a file
            for each_category in list_of_url_categories:
                writer_url_categories_template.writerow([
                    each_category["category"],
                    each_category["action"],
                    each_category["user_type"],
                    each_category["label"],
                    each_category["description"],
                ])
            f_url_categories_template.flush()

            console.print(f"URL categories template file (`{settings.URL_CATEGORIES_TEMPLATE_FILENAME}`) has been created.\n"
                  f"Now you can clone it having removed the `template_` prefix, update the actions and user group names "
                  f"as required, and then re-run this script")

    except pan.xapi.PanXapiError as e:
        console.print("\n\n[bold red]!!! ERROR !!![/bold red] Failed to connect to the PAN-OS device:", e)
        sys.exit()

    return list_of_built_in_url_categories
