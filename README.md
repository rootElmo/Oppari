# Opinnäytetyö (Eurorack-syntetisaattorin sekvensserin kehitys ja tekninen monistaminen)

Elmo Rohula

Haaga-Helia ammattikorkeakoulu

7.3.2021

## Tiivistelmä

**Tekijä(t)**

  * Elmo Rohula

**Koulutusohjelma**

  * Tietojenkäsittely

**Raportin/Opinnäytetyön nimi**

  * Eurorack-syntetisaattorin sekvensserin kehitys ja tekninen monistaminen

**Tiivistelmä**

Opinnäytetyö keskittyy sulautetun järjestelmän luomiseen Arduino-kehitysalustalle sopivilla työkaluilla. Luodun sulautetun järjestelmän prototyyppi tullaan saattamaan valmiiksi teknistä monistamista varten. Teknistä monistamista varten laitteelle tullaan luomaan piirilevypiirustukset, piirustukset mahdollisesti tarvittavasta etupaneelista, sekä kustannusarvioit projektin viemisestä sarjatuotantoon.

Luotu laite tulee olemaan sekvensseri Eurorack-syntetisaattoreille.

Laitteen luominen tullaan käymään läpi tarkemmin tarkastelemalla tarvittavia teknologioita, työkaluja, sekä laitteen lähdekoodia ja toimintaa. Laitteen luomisen prosessi käsittää sisälleen kaiken alkuperäisestä ideasta aina valmiin piirilevyn luomiseen komponentteineen.

Projektin monistamisen prosessi tullaan käymään läpi samalla tavalla kuin itse laitteen luomisen prosessi. Tekninen monistaminen pitää sisällään mm. prototyypin lopullisten komponenttien päättämisen, sarjatuotannon kustannusten arvioimisen, sekä lopullisen rakennusprosessin ajoittamisen sarjatuotannon kustannuksiin laskemista varten.

Lopussa arvioidaan itse projektin onnistumista, sekä monistamisprosessin hyödyllisyyttä vastaavien projektien näkökulmasta.

**Asiasanat**

Eurorack, Arduino, sulautettu järjestelmä, monistaminen, c++, sekvensseri

## 1. Johdanto

// tekstiä

**1.1 Tavoitteet ja rajaus**

Opinnäytetyön tavoitteena on selkeyttää teknisen monistamisen prosessia. Opinnäytetyön aikana luotu Eurorack-sekvensseri toimii tämän teknisen monistamisen kohteena. Näihin tavoitteisiin pääsemiseen vaaditaan myös itse laitteen luominen, joten valmis laite, tai ainakin sen pitkälle viety prototyyppi syntyy myös projektin aikana.

// Päätä alle julkaisun lisenssi!!!!

Laitteen kehittämisestä syntyvä dokumentaatio, lähdekoodi, sekä kytkentäkaaviot tullaan julkaisemaan GitHubissa.

Valmiita opinnäytetöitä sulautettujen järjestelmien luomisesta löytyy useita, mutta harvassa ollaan edes mietitty niiden tuotoksien monistamista, taikka viemistä kevyestä prototyypistä eteenpäin. Tämän opinnäytetyön teknisen monistamisen prosessin kuvaaminen ja läpikäynti tulisi auttamaan muiden vastaavien projektien viemisessä eteenpäin kohti sarjatuotantoa. Vaikka tämän opinnäytetyön puitteissa keskitytään hyvin spesifiin laitteeseen, sekä suhteellisen suureen teoreettiseen tuotantomäärään teknisen monistamisen osuudessa, pystyisi vastaavilla prosesseilla ja työkaluilla luomaan pienemmän mittakaavan sarjatuotantoa harrastus-, koulu-, tai yritysprojekteihin.

Tekninen monistaminen tämän opinnäytetyön puitteissa keskittyy yhden tai muutaman valmiin laitteen rakennukseen, rakennuksen keston ajoittamiseen kustannusarvioita varten, sekä sarjatuotannon kustannuksien arviointiin. Näistä eri kustannusarvioista saadaan laitekohtainen hinta, kun arvoidaan teknisen monistamisen tuloksia.

Opinnäytetyön teknisen monistamisen prosessi ei pidä sisällään monistettavan laitteen tuotteeksi viemistä. Vaikka monistamisprosessista syntyy kustannusarvioita, ovat nämä pelkästään arvioita laitteen sarjatuotannosta. Tuotteistamista varten tulisi tehdä selvitys kilpailijoista, markkinoista, sekä selvitys siitä, olisiko kukaan todellisuudessa valmis ostamaan mahdollisesti valmistuvaa tuotetta.

**1.2 Käsitteet**

// Etsi näille myös lähteitä.

  * Arduino - 
  * Teensy - 
  * Eurorack - Modulaarinen syntetisaattoriformaatti, jossa kokonainen syntetisaattori koostuu useasta eri moduulista.
  * Rackunit (??) - 
  * HP (Horizontal Pitch) -
  * CV (Control Voltage) - 
  * Gate -
  * Oskillaattori - 
  * Sekvensseri - Musiikin tuotannossa käytetty ylensä elektroninen laite tai ohjelmisto, jonka avulla voidaan toistaa, muokata ja soittaa musikaalisia sekvenssejä.
  * Step -
  * PPQ (Parts Per Quarter) -
  * DAC (Digital to Analog Converter) -
  * SPI (Serial Peripheral Interface) -
  * PCB (Printed Circuit Board) - 

## 2. Taustaa

Tämän luvun tarkoituksena on avata opinnäytetyön taustoja liittyen luotuun Eurorack-sekvensseriin, tekniseen monistamiseen, sekä erinäisiin kehitysmenetelmiin joita laitteen kehittämisessä tarvitaan.

**2.1 Eurorack**

Eurorack-syntetisaattori formaatti on Dieter Doepferin vuonna 1996 kehittämä formaatti modulaariselle syntetisaattorille [(reverb)](https://reverb.com/news/beginners-guide-to-eurorack-case-basics-oscillators-filters). Eurorack formaatille olennaisia piirteitä ovat sen pienikokoisuus muihin modulaarisiin syntetisaattoriformaatteihin verrattuna. Eurorack-syntetisaattorissa moduulien korkeus on noin kolme räkkiyksikköä (tai 128,5mm). Laskennallisesti korkeuden tulisi olla 133,4mm, mutta moduuleitten korkeudessa ollaan otettu huomioon kiinnityskiskojen "lippa". [(doepfer).](http://www.doepfer.de/a100_man/a100m_e.htm) Alunperin Eurorack-formaatti oli yhteensopiva 19 tuuman räkki standardin kanssa, mutta vuosien varrella erinäiset valmistajat, sekä Doepfer itse ovat valmistaneet standardia leveämpiä ja kapeampia koteloita.

Eurorack-syntetisaattorit, sekä modulaariset syntetisaattorit yleisesti eivät sisällä koskettimistoa ja harvoin koskettimiston integroiminen modulaariseen syntetisaattoriin on mahdollista. Eurorack-syntetisaattorin eri moduuleita ohjataan käyttäen erinäisiä ohjausjännitteitä (Control Voltage/CV) [(doepfer)](http://www.doepfer.de/a100_man/a100t_e.htm). Ohjausjännite on analoginen signaali, joka syötetään yhteen tai useampaan moduliin, joka tuottaa muutoksen syntetisaattorin signaaliketjussa suhteutettuna ohjausjännitteen määrään. Esimerkiksi oskillaattorin sävelkorkeuden nostaminen yhdellä oktaavilla vastaa yhden voltin korotusta ohjausjännitteessä 1V/Oct-standardilla [(learningmodular)](https://learningmodular.com/glossary/1-voct/).

Eurorack-syntetisaattoreita on myös mahdollista ohjata ulkopuolisilla laitteistoilla, sekä ohjelmistoilla, mutta näiden lähettämät signaalit muutetaan aina analogiseen muotoon.

// Esimerkkejä järjestelmistä.

**2.2 Sulautettu järjestelmä**

Sulautettu järjestelmä on koostuu erinäisistä tietokoneen fyysisistä osista, sekä ohjelmistosta, jolla järjestelmä suorittaa siltä vaadittuja toimintoja [(barrgroup)](https://barrgroup.com/embedded-systems/glossary-e). Sulautettu järjestelmä toimii usein joko itsenäisesti, tai osana laajempaa tietoteknistä järjestelmää. Siinä missä työasemina käytetyt tietokoneet käyttävät usein graafista käyttöliittymää, sekä erinäisiä ulkoisia ohjauslaitteita kuten mm. hiiret ja näppäimistöt, sulautettu järjestelmä ei välttämättä sisällä näitä ollenkaan. Esimerkiksi puhelimet ja älykellot ovat sulautettuja järjestelmiä.

Tämän opinnäytetyön aikana valmistuva sekvensseri on myös sulautettu järjestelmä. Laite itsessään ei pidä sisällään mitään käyttöjärjestelmää ja sen ensisijainen tarkoitus on toimia Eurorack-syntetisaattorin sekvensserinä.

**2.3 Tekninen monistaminen**

// Listaa tänne oppareita/julkaisuja, joissa prototyyppi/valmis laite ei koskaan joudu teknisen monistamisen kohteeksi.

Tekninen monistaminen tämän opinnäytetyön puitteissa tarkoittaa jonkin teknisen laitteen monistamista fyysisesti. Teknisen monistamisen vaiheessa jostakin laitteesta, joka on ylensä prototyyppi, pyritään luomaan helposti monistettavissa oleva kokonaisuus. Sulautettujen järjestelmien prototyypit voivat olla käsin rakennettuja ja niissä voi olla paljon ei-toivottuja ominaisuuksia, joita mahdollisesti lopullisessa laitteessa ei tulisi olemaan. 

## x Sekvensserin prototyypin rakentaminen

// Tässä luvussa käsitellään sekvensserin prototyypin rakentamista

**x.1 Ohjelmisto**

// Ohjelmakoodin läpikäyntiä tärkeimmiltä komponenteilta. Kerro myös menetelmistä ja työkaluista (VSCode, PlatformIO, Teensy LC)

**x.1.1 Käyttäjän syötteet**

// Käyttäjän syötteidin luku, sekä käsittely.
// MCP23S17 ja "Näppäimistö"
// Enkooderi
// Mahdolliset ulkoiset clock in jne. (PPQ, MIDI clock)

**x.1.2 Sekvensseri**

// Sekvenssin soitto, muokkaus, luonti, tallennus

**x.1.3 Eurorack yhteensopivuus**

// DAC (tietty malli ja kirjasto, jota käytetty)
// 1V/oct, Gate, clock jne.

**x.2 Fyysinen laitteisto**

// Teensy LC, leipälaudat, johdot, DACit, GPIO extenderit jne. Tähän myös kytkentäkaavoista, sekä laitteen eri iteraatioista (ekassa protossa enkooderi, tokassa button matrix jne.)

**x.3 Kokoonpano**

// Lopullisen prototyypin rakennus ja kokoonpano. Tähän juotoksista, käytetyistä materiaaleista jne. Vertaa muihin opinnäytetöihin/julkaisuihin, joissa aihe päättyy tähän vaiheeseen, eikä teknistä monistamista mietitä.

## x Tekninen monistaminen

Tässä luvussa käydään läpi tekninen monistaminen, sekä sen vaatimat vaiheet. Tässä voidaan tarkastella muutoksia monistettavan version, sekä prototyypin välillä (esim. läpiladottavat komponentit vs. SMD, tavalliset nappikytkimet vs. Cherry MX tai vastaavat "kunnon kytkimet").

**x.1 Piirilevyn, sekä etupaneelin piirto**

// KiCad, kytkentäkaavat, silkscreen piirto.
// Etupaneelin leikkaukset piirilevyn mukaan.

**x.2 Komponenttien listaus ja tilaus**

// BOM
// Mouser, JLCPCB/AllPCB,/Seeed jne.

**x.3 Monistamisen laskelmat (otsikko työn alla)**

// BOM * haluttujen laitteiden määrä
// Muutaman laitteen käsin asennus (Tätä ennen käytävä lopullisen laitteen rakennus ja ajoitus)

## Lähteet

// lainausjärjestyksessä.
// Lainausmerkinnät/viittaukset varsinaisessa opinnäytetyössä eivät valmiita
// Näihinkin tarvittavat tiedot vvvvvvv

1. [Reverb - Eurorack formaatti](https://reverb.com/news/beginners-guide-to-eurorack-case-basics-oscillators-filters) luettu 7.3.2021
2. [Doepfer - A-100 construction details](http://www.doepfer.de/a100_man/a100m_e.htm) Luettu 7.3.2021
3. [Doepfer - A-100 technical details](http://www.doepfer.de/a100_man/a100t_e.htm) Luettu 10.3.2021
4. [learningmodular - 1 v/oct](https://learningmodular.com/glossary/1-voct/) Luettu 10.3.2021
5. [barrgroup - embedded systems - glossary e](https://barrgroup.com/embedded-systems/glossary-e)