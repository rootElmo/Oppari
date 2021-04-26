**Tämä on vielä keskeneräinen opinnäytetyö**, mutta voit lueskella sitä jo rullaamalla alaspäin.

![pcb_done002](./imgs/pcb_done002.png)

_KISSen testailua_

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

Arduino a. What is Arduino?. Luettavissa: https://www.arduino.cc/en/Guide/Introduction. Luettu 26.4.2021.

Arduino b.

  * Arduino - Avoimen lähdekoodin alusta elektroniikka projektien kehitykseen [(Arduino a)](https://www.arduino.cc/en/Guide/Introduction).
  * Teensy - Arduinon kaltainen, elektroniikka projektien kehitysalusta [(PJRC)](https://www.pjrc.com/teensy/).
  * Eurorack - De-facto standardi pienikokoisille modulaarisille syntetisaattoreille [(Leonora Tindall 2020)](https://nora.codes/post/modular-synthesis-and-unix/).
  * CV (Control Voltage) - Ohjausjännite, jolla voidaan ohjata analogisten syntetisaattoreiden eri osia.
  * Gate - 
  * Oskillaattori - 
  * Sekvensseri - Musiikin tuotannossa käytetty ylensä elektroninen laite tai ohjelmisto, jonka avulla voidaan toistaa, muokata ja soittaa musikaalisia sekvenssejä.
  * Step - Askel. Sekvenssereissä käytetty määre, jolla mitataan sekvenssin pituutta.
  * DAC (Digital to Analog Converter) - Mikropiiri, joka muuttaa sille annetun digitaalisen signaalin analogiseksi jännitteeksi. (Tähän lähde)
  * SPI (Serial Peripheral Interface) - Tietoteknisten järjestelmiän käyttämä väylä, jonka avulla kokonaisen laitteen eri komponentit keskustelevat keskenään. (Etsi tähän lähde)
  * PCB (Printed Circuit Board) - Piirilevy.

## 2. Taustaa

  Tämän luvun tarkoituksena on avata opinnäytetyön taustoja liittyen luotuun Eurorack-sekvensseriin, tekniseen monistamiseen, sekä erinäisiin kehitysmenetelmiin joita laitteen kehittämisessä tarvitaan. 
  // Tähän ehdottomasti vähän enemmän tekstiä.

**2.1 Eurorack**

Eurorack-syntetisaattori formaatti on Dieter Doepferin vuonna 1996 kehittämä formaatti modulaariselle syntetisaattorille [(Reverb 2020)](https://reverb.com/news/beginners-guide-to-eurorack-case-basics-oscillators-filters). Eurorack syntetisaattoriformaatti perustuu 19 tuuman räkki standardille. Eurorack-syntetisaattorissa moduulien korkeus on noin kolme räkkiyksikköä (tai 128,5mm). Laskennallisesti korkeuden tulisi olla 133,4mm, mutta moduuleitten korkeudessa ollaan otettu huomioon kiinnityskiskojen "lippa". [(Doepfer a.)](http://www.doepfer.de/a100_man/a100m_e.htm) 

Eurorack-syntetisaattorit, sekä modulaariset syntetisaattorit yleisesti eivät sisällä koskettimistoa ja harvoin koskettimiston integroiminen modulaariseen syntetisaattoriin on mahdollista. Eurorack-syntetisaattorin eri moduuleita ohjataan käyttäen erinäisiä ohjausjännitteitä (Control Voltage/CV) [(Doepfer b)](http://www.doepfer.de/a100_man/a100t_e.htm). Ohjausjännite on analoginen signaali, joka syötetään yhteen tai useampaan moduliin, joka tuottaa muutoksen syntetisaattorin signaaliketjussa suhteutettuna ohjausjännitteen määrään. Esimerkiksi oskillaattorin sävelkorkeuden nostaminen yhdellä oktaavilla vastaa yhden voltin korotusta ohjausjännitteessä 1V/Oct-standardilla [(learningmodular)](https://learningmodular.com/glossary/1-voct/).

Eurorack-syntetisaattoreita on myös mahdollista ohjata ulkopuolisilla laitteistoilla, sekä ohjelmistoilla, mutta näiden lähettämät signaalit muutetaan aina analogiseen muotoon.

  // Esimerkkejä järjestelmistä.

**2.2 Sulautettu järjestelmä**

Sulautettu järjestelmä on digitalisoitu järjestelmä, jonka toiminta on suppeampaa kuin tavallisen tietokoneen. Sulautettu järjestelmä on vain tiettyä tarkoitusta varten luotu järjestelmä. Sulautetuille järjestelmille on myös tyypillistä laskentaresurssien niukkuus, sekä suppea tuki ulkoisille laitteille. (Elicia White 2011, luku 1.)

Tämän opinnäytetyön aikana valmistuva sekvensseri on myös sulautettu järjestelmä. Laite itsessään ei pidä sisällään mitään käyttöjärjestelmää ja sen ensisijainen tarkoitus on toimia Eurorack-syntetisaattorin sekvensserinä.

**2.3 Tekninen monistaminen**

  // Listaa tänne oppareita/julkaisuja, joissa prototyyppi/valmis laite ei koskaan joudu teknisen monistamisen kohteeksi.

Tekninen monistaminen tämän opinnäytetyön puitteissa tarkoittaa opinnäytetyön aikana valmistuvan laitteen laitteen prototyypin kehittämistä siihen tilaan, että käsityötä vaativat prosessit ovat minimoitu ja suuri osa työstä saatettu automatisoitavaan tilaan. Laitteen prototyyppivaiheessa rakennus vaatii paljon komponenttien asettelua ja kolvaamista käsin.

Tekninen monistaminen voidaan nähdä osana "rapid prototyping" teknologioita. "Rapid prototyping" teknologiat sekä prosessit ovat teollisuudessa käytettyjä prosesseja, joilla pyritään nopeuttamaan tuotteiden ja prototyyppien valmistusta. Näihin teknologioihin kuuluu esimerkiksi 3D-tulostus (/*Vaihda lähde, kirjoita uudestaan.*/ Kai, C. C., & Fai, L. K. (1997). Rapid Prototyping. Nanyang technological university). Esimerkiksi opinnäytetyön laitteen piirilevyt piirretään CAD-ohjelmistolla, jonka jälkeen piirilevyt tilataan niitä valmistavalta tehtaalta. Tällä prosessilla vältyytään piirilevyjen valmistamiselta itse ja lopputuloksena ovat yhdenmukaiset piirilevyt.

Valmistuvan laitteen teknisesti monistettava muoto ei tulisi sisältämään kuin pakollisen määrän komponentteja, jotka vaativat ihmisen niiden asennukseen. Esimerkiksi laitteen piirilevyjen valmistuksen aikana olisi mahdollista myös juottaa suuri osa komponenteista tehtaalla, jos laite rakentuisi pintaliitoskomponenteista.

**2.4 Projektin rakenne ja prosessit**

Opinnäytetyön projekti prototyypistä teknisesti monistettavaan laitteeseen on melko laaja. Projektin prosessi on osittain kuvattuna projektisuunnitelmassa liitteessä 1, "Projektin tehtävät, työmäärät ja ajoitus". Projektin tehtävistä ei kuitenkaan suoranaisestä käy ilmi laitteen rakennuksen prosessi alusta loppuun. Prosessi kulkisi pääpiirteittäin seuraavasti:

  * Laitteen suunnittelu. Mietitään mahdollisesti käytettävät teknologiat ja käydään läpi aiemmin tuotettuja vastaavanlaisia projekteja/laitteita.
  * Prototyypin rakentamisen aloittaminen. Aloitetaan muutamalla keskeisellä ominaisuudella laitteen toiminnan kannalta ja rakennetaan muita ominaisuuksia siihen päälle.
  * Kaikkien yksittäisten ominaisuuksien kokeilu prototyypin aikana. Tässä vaiheessa kaikki lopulliselta laitteelta vaaditut tai toivotut ominaisuudet ovat käyty läpi.
  * Laitteen käyttöliittymän suunnittelu. Kokeillaan eri keinoilla mahdollisesti sopivaa käyttöliittymän muotoa.
  * Piirilevyjen ja etupaanelien suunnittelu, piirtäminen ja tilaus. Tässä vaiheessa prototyypin aikana syntyneet piirit käännetään piirilevylle luotujen kytkentäkaavojen mukaan. Myös etupaneeli hahmotellan piirilevyn, sekä aiemmin suunniteltujen toimintojen mukaan.
  * Komponenttien listaus, sekä tilaus. Prototyypin aikana käytetyt komponentit listataan ja tästä listauksesta luodaan projektille "Bill of Materials", jonka avulla komponentteja on mahdollista tilata yhteen tai useampaan vastaavaan laitteeseen.
  * Laitteen rakentaminen. Tässä vaiheessa rakennetaan yksi tai useampi teknisesti monistettava laite ja ajoitetaan rakennus lopullisia laskelmia varten.
  * Laskelmien teko ja tulosten läpikäynti. Tässä vaiheessa lasketaan laitteen rakennuksen ja suunnittelun kulut, sekä näiden perusteella tehdään laskelmia mahdollista sarjatuotantoa varten. Projektin tuloksia käydään myös läpi niiltä osin kun ne ovat merkittäviä.


## x Tutkimuksen tavoite ja hyödyt (viilaa vielä otsikkoa)

Tässä opinnäytetyössä haluan tarkastella jo kirjoitettujen opinnäytetöiden, sekä artikkelien pohjalta teknistä monistamista. Prototyyppien rakennusta käsitteleviä opinnäytetöitä on monia, mutta harvoissa mietitään prototyypin viemistä monistettavaan muotoon.

Julkaistuista opinnäytetöistä ja artikkeleista katsotaan kuinka kirjoittajat ovat luoneet toimivan prototyypin, mutta jättäneet avoimeksi laitteen jatkokehityksen. Näiden töiden myötä annan myös ehdotuksia ja ideoita siitä, kuinka laitteita oltaisiin voitu viedä teknisesti monistettavampaan muotoon.

Opinnäytetyön tuloksista alasta kiinnostuneet harrastajat, opiskelijat ja ehkä jopa ammattilaiset saavat yleisen kuvan siitä, mitä sulautetun järjestelmän prototyypin luominen vaatii. Tämän lisäksi opinnäytetyön tavoitteena on antaa yleistä kuvaa prosesseista, joilla luotu prototyyppi voitaisiin muokata teknisesti monistettavaan muotoon.

**x.1 Esimerkkityö 1 (Arduino-pohjainen laite liikkeen ja lämpötilan monitorointiin)**

  // Aleksi Karppila - Arduino-pohjainen laite liikkeen ja lämpötilan monitorointiin (2014)

Aleksi Karppilan opinnäytetyö "Arduino-pohjainen laite liikkeen ja lämpötilan monitorointiin" käsittelee Arduino-pohjaisen monitorointilaitteen rakentamista (Karppila 2014, 1). Projektin aikana Karppila rakentaa toimivan laitteen, käy läpi sen toimintaa, ohjelmointia, sekä yleisiä käsitteitä Arduino-kehitysalustaan liittyen.

Karpilla kertoo valmistuksessa ja suunnittelussa pyrkineensä yksinkertaisuuteen, jotta laitteen toiminta olisi moitteetonta ja luodulla laitteella olisi mahdollisimman laaja kohderyhmä (Karppila 2014, 13). Kuitenkin lopullinen laite, jota opinnäytetyössä on kuvattu muistuttaa pitkälti prototyypinomaista laitetta, jossa kytkennät ovat tehty hyppylangoilla korkytkentälaudan kautta. 

/*Tähän vaikka kuva Karppilan opinnäytetyön laitteesta*/

Jotta Karppilan laite saavuttaisi halutun laajan kohderyhmänsä tulisi laitteen kytkentöjen olla pysyviä ja laitteen eri komponenttien osana yhtä kokonaisuutta. Karppilan laitteen kohderyhmää rajoittaa näin ollen se, että laitetta tulisi harkitsemaan vain ne, joilla olisi osaamista ja halukkuutta rakentaa käsin Arduino-kehitysalustalle oma laitteensa.

Laitetta ei välttämättä olisi tarvinnut koota täysin omaksi kokonaisuudekseen, vaan Arduino-alustan komponenteista oltaisiin voitu rakentaa "Arduino-kilpi". Arduino-kilvet ovat valmiita laitekokonaisuuksia, jotka voidaan kytkeä suoraan Arduino-kehitysalustaan [(Arduino b)](https://www.arduino.cc/en/Main/arduinoShields). Laitteen käyttäjän olisi vielä kuitenkin tarvinnut ohjelmoida laite.

  // Viittaa täällä vielä konkreettisiin prosesseihin, joita Karppila olisi voinut tehdä (Kicad, kytkentäkaavat jne.) Viittaa tähän opinnäytetyön ja projektin rakennusvaiheisiin

**x.2 Esimerkkityö 2**

  // Tähän esimerkkityö 2
  // Käy läpi samalla tavalla kuin ylemmässä kohdassa.
  // Etsi jokin samantyylinen, mutta sellainen työ, joka on käynyt projektissa eri työvaiheita kuin Karppilan työ


## x Sekvensserin prototyypin rakentaminen

  // Tässä luvussa käsitellään sekvensserin prototyypin rakentamista

Sekvensserin prototyypin rakennus tapahtui asteittain ja jokaista laitteen osaa ja toiminnallisuutta pyrittiin testaamaan yksitellen, sekä osana suurempaa kokonaisuutta. Laitteen pohjana ja inspiraationa toimi pitkälti Matthew Cieplakin "Super Sixteen"-sekvensseri.

Rakennuksessa käytettiin pelkästään koekytkentälautaa projektin alussa, mutta projektin edetessä ja komponenttien määrän kasvaessa joitain laitteen osia jouduttiin rakentamaan omiksi irrallisiksi kokonaisuuksiksiin.

**x.1 Ohjelmisto**

  // Ohjelmakoodin läpikäyntiä tärkeimmiltä komponenteilta. Kerro myös menetelmistä ja työkaluista (VSCode, PlatformIO, Teensy LC)

Laitteen lähdekoodi kirjoitettiin C++-ohjelmointikielellä Arduino koodipohjalle. Kehitysympäristönä toimi PlatformIO, joka on Arduino-yhteensopiva integroitu kehitysympäristö Visual Studio Codelle [(PlatformIO)](https://docs.platformio.org/en/latest/what-is-platformio.html). Kehitysalustana laitteessa toimii Teensy LC. Lopullisen laitteen on suunniteltu käyttävän ATmega328 mikroprosessoria, mutta kehityksen aikana Teensy LC oli pienemmän koonsa takia parempi vaihtoehto kuin esimerkiksi Arduino Uno.

**x.1.1 Käyttäjän syötteet**

Sekvensserin toiminnan kannalta muutamia käyttäjän syötteitä pitäisi pystyä lukemaan. Laitteen suunnitteluvaiheessa 16 painikkeen painikematriisi tulisi vastaamaan sekvenssin askeleen valinnasta, sekä funktiopainikkeen kanssa käytettynä erinäisistä funktioista. Käyttäjän tulisi myös pystyä muokkaamaan liukuvia arvoja, kuten sekvenssin askeleiden nuottien korkeutta, tempoa, sekä erinäisiä asetuksia, jotka vaikuttavat sekvensserin toimintaan. Liukuvien arvojen muokkaamiseen laite käyttää 24 askeleen enkooderia. Laitteessa on myös potentiometri, jolla käyttäjä voi säätä nuottien välistä liukumaa.

Painikematriisia luetaan MCP23S17 GPIO-laajentimen kanssa. Laitteella voidaan SPI-väylän välityksellä käyttää maksimissaan 16 GPIO-lisäpinniä [(Microchip)](https://ww1.microchip.com/downloads/en/devicedoc/20001952c.pdf). Koska MCP23S17 vaatii onnistuneeseen tiedon välitykseen yhteensä 4 GPIO-pinniä mikroprosessorista saadaan MCP23S17:ta käyttämällä laajennettua mikroprosessorin GPIO-pinnien määrää 12:sta.

![buttonmatrix001](./imgs/buttonmatrix001.png)

_Painikematriisin skannausta prototyyppi-vaiheessa MCP23S17:n avulla._

Resurssien säästämiseksi laitteen jokaisella funktiolla ei ole erillistä painiketta. Laitteesta löytyisi "funktio"-painike, jota painettaessa käyttäjä voisi käyttää laitteen painikematriisien painikkeita sekundaaristen funktioiden suorittamiseen. Tällöin 16 painikkeella pystyisiin teoreettisesti suorittamaan 32 eri toimintoa.

![buttons001](./imgs/buttons001.jpg)

_Painikkeiden sekundaariset funktiot lueteltu panikesarakkeittain_

Käyttäjä voi myös lähettää signaaleja muista Eurorack-moduuleista. Laitteessa on kaksi sisääntuloa signaaleille: "Clock" ja "Reset". "Clock"-signaalilla käyttäjä voi synkronoida laitteen toisten sekvensserien tai ohjainlaitteiden kanssa lähettämällä pulsseja sisääntuloon. "Reset"-signaalilla käyttäjä voi pysäyttää käynnissä olevan sekvenssin ulkoisella pulssilla. 

![inputs001](./imgs/inputs001.jpg)

_Signaalien sisään- ja ulostulot. Sisöäntulevat signaalit mustalla tekstillä valkoisella taustalla_

**x.1.2 Sekvensseri**

  // Sekvenssin soitto, muokkaus, luonti, tallennus



**x.1.3 Eurorack yhteensopivuus**

  // DAC (tietty malli ja kirjasto, jota käytetty)
  // 1V/oct, Gate, clock jne.

**x.2 Fyysinen laitteisto**

  // Teensy LC, leipälaudat, johdot, DACit, GPIO extenderit jne. Tähän myös kytkentäkaavoista, sekä laitteen eri iteraatioista (ekassa protossa enkooderi, tokassa button matrix jne.)
  // Tähän voi laittaa kivan kuvajatkumon prototyypin etenemisestä (kuvat prototyping001-003)

## x Tekninen monistaminen

  // Tässä luvussa käydään läpi tekninen monistaminen, sekä sen vaatimat vaiheet. Tässä voidaan tarkastella muutoksia monistettavan version, sekä prototyypin välillä (esim. läpiladottavat komponentit vs. SMD, tavalliset nappikytkimet vs. Cherry MX tai vastaavat "kunnon kytkimet").

Prototyypin kaikkien merkittävien komponenttien testauksen jälkeen seuraava työvaihe oli suunnitella laite monistettavaan muotoon. Laitteen monistaminen toiselle koekytkentälaudalle olisi erittäin työläs prosessi, eikä laitetta voisi millään tapaa käyttää integroituna osana Eurorack-syntetisaattoria laitteen suuren koon takia.

Jotta laite olisi teknisesti monistettava täytyisi sen manuaalisia asennusvaiheita eliminoida niin pitkälle kuin mahdollista. Näin voitaisiin tehdä mm. piirilevyjen kanssa niin, että käytettäisiin niin paljon pintaliitoskomponentteja kuin mahdollista. Pintaliitoskomponentit ovat perinteisiä läpiladottavia komponentteja huomattavasti pienempiä ja niiden asennus piirilevyille voidaan useimmiten suorittaa piirilevyjä tuottavilla tehtailla.

![smdtht001](./imgs/smdtht001.jpg)

_100 kilo-Ohmin vastuksia. Yllä yksi läpiladottava ja alla neljä pintaliitosvastusta_

![jlcpcb001](./imgs/jlcpcb001.png)

_JLCPCB tarjoaa piirilevyjen valmistuksen yhteydessä "SMT Assembly"-palvelua_

**x.1 Piirilevyn, sekä etupaneelin piirto**

Laiten prototyypin valmistuttua siihen vaiheeseen, että kaikki kriittisimmät toiminnot olivat valmiita alkoi piirilevyn sekä etupaneelin suunnittelu. Etupaneelin muotoilu noudatti pitkälti piirilevypiirroksen luomia rajoitteita. Piirilevypiirros taas pohjautui käyttöliittymän suunnitteluvaiheessa tehtyihin päätöksiin. Prototyyppivaiheen aikana ylläpidetyn kytkentäkaavan avulla prototyypin kytkennät oli helppo kääntää piirilevyllä komponenttien välisiksi juoviksi, kun kytkentäkaavaa ei erikseen tarvinnut piirtää tyhjästä.

Piirilevy, sekä etupaneeli suunniteltin KiCad-ohjelmistolla. Koska piirilevyissä käytetty FR4-lasikuitukomposiitti on ominaisuuksiltaan suhteellisen vahvaa käy se materiaaliksi myös etupaneeleissa.

Etupaneelin grafiikoiden suunnittelussa käytettiin KiCadin lisäksi myös GIMP-kuvankäsittelyohjelmaa. Projektin tavoitteena ei ollut luoda yhteneväistä estetiikkaa laitteelle, mutta pyrkimys oli löytää yhdenmukainen graafinen ulkoasu. Piirilevystä otettiin kaikki kriittiset mitat, jotka määräisivät mm. enkooderin sekä potentiometrin vaativat reijät.

**x.1.1 Piirilevy**

Teknisen monistamisen helpottamiseksi piirilevyllä päätettiin käyttää pintaliitoskomponentteja niin paljon kuin mahdollista. Pintaliitoskomponentit on mahdollista juotatuttaa kiinni piirilevyyn valmiiksi monilla piirilevyjä valmistavilla tehtailla. Tämä laskisi merkittävästi laitteen rakennusaikaa ja näin laskisi laitteen mahdollista katteetonta hintaa.

Piirilevyn piirron aikana ensiksi asetettiin paikoilleen käyttöliittymän kriittisimmät komponentit, kuten painikkeet, segmenttinäytöt sekä ulostulojakit.

![kicad_in_process001](./imgs/kicad_in_process001.png)

_Piirilevyn mitat päätetty, sekä kriittisimmät komponentit asetettu paikoilleen._

Laitteen komponentit sijoitettiin piirilevylle "funktioittain"; esimerkiksi segmenttinäytön ohjauksesta vastaavat piirit, vastukset ja transistorit reititettiin yhtenä kokonaisuutena. Tämän jälkeen näyttö kokonaisuutena sijoitettiin piirilevylle muiden komponenttien sekaan. Tarvittaessa komponentteja siirrettiin toisten tieltä, sekä reititystä optimoitiin.

![kicad_in_process002](./imgs/kicad_in_process002.png)

_Segmenttinäytöt, sekä niiden ohjauksesta vastaavat komponentit._

Piirien reititystapahtuu seuraamalla kytkentäkaaviota, sekä piirilevyn piirto-ohjelman "ratsnest"-verkkoa, joka näyttää kaikki piirilevyllä kytkemättä olevat piirit. Vaikka "ratsnest" tarjoaa helpon visuaalisen työkalun reititykseen, kytkentäkaavion seuraaminen on silti tärkeää.

![pcb_routing001](./imgs/pcb_routing001.png)

_Osittain kytketty mikroprosessori. Avoimet piirit näkyvät valkoisina viivoina._

Lopuksi kun kaikki komponentit olivat paikoillaan ja piirit reititetty otettiin käyttöliittymän kannalta kriittisistä komponenteista mitat suhteessa toisiinsa. Tämä helpottaisi etupaneelin suunnittelua. Piirilevyn piirto-ohjelmasta löytyy työkalu, jolla eri komponenttien välisiä etäisyyksiä pystyy mittaamaan ja asettamaan näkyville tasoille, jotka voidaan myöhemmin joko tulostaa tai kääntä pdf-tiedostoksi.

![pcb_measurements002](./imgs/pcb_measurements002.png)

_Funktiopainikkeiden leikkausalueen mittausta näkyvälle tasolle._

![pcb_measurements001](./imgs/pcb_measurements001.png)

_Mittojen vektoripiirros. Sinisellä värillä komponenttien keskinäiset mitat ja punaisella värillä etupaneelin mitat._

**x.1.2 Etupaneeli**

Etupaneelin piirto oli suhteellisen nopea prosessi, sillä Eurorack-formaatti määrittelee pitkälti paneelien mahdolliset mitat ja piirilevyn komponenttien asettelu määräsi mahdolliset reiät ja leikkaukset etupaneeliin. Käyttöliittymää laitteelle prototyypattiin paperilla, jotta saataisiin jonkin näköinen käsitys laitteen "käsituntumasta".

![ui_planning001](./imgs/ui_planning001.jpg)

_Etupaneelin prototyyppäystä paperilla, näppäinhatuilla ja erinäisillä laitteesta löytyvillä komponenteilla._

Paneelin mittojen määrittelyn ja kiinnitysruuvien reikien jälkeen paneeliin leikattiin alueet kytkimille, sekä segmenttinäytöille. Myös potentiometrien, sekä ulos- ja sisääntulojakkien reiät asetettiin kohdilleen.

![panel001](./imgs/panel001.png)

_Etupaneeli oikeissa mitoissaan_

![panel003](./imgs/panel003.png)

_Etupaneeli kaikkine vaadittavine leikkauksineen_

  // Tähän tekstiä paneelin muiden leikkausten ja reikien teosta.

Etupaneelin grafiikat luotiin GIMP-kuvankäsittelyohjelmalla, jonka jälkeen luodut kuvat muutettiin KiCadille sopivaan "footprint"-muotoon. Jokainen yksittäinen teksti tai muu graafinen elementti on oma "komponenttinsa" piirilevyllä. Jokaisen kuvan resoluutio asetettiin olemaan 1000ppcm, jolloin 1000 pixeliä leveys-, tai korkeussuunnassa vastaisi yhtä senttimetriä leveys-, tai korkeussuunnassa etupaneelilla. KiCad-ohjelmasta löytää aliohjelma "bitmap2component.exe", jolla kuvat muutetaan haluttuun muotoon. Ohjelma tunnistaa kuvan tarkkuuden automaattisesti.

![panel002](./imgs/panel002.png)

_Potentiometrin kääntösädettä kuvaava kaari GIMP-kuvankäsittelyohjelmassa (vas.) ja valmiissa etupaneelipiirroksessa (oik.)_

![panel004](./imgs/panel004.png)

_Valmiin etupaneelin 3D-renderi_

**x.2 Komponenttien listaus ja tilaus**

  // BOM
  // Mouser

KiCad tarjoaa valmiit työkalut osalistojen luomiseen kytkentäkaavojen pohjalta, joka helpottaa huomattavasti projektien tekoa. Osalistoja kutsutaan yleisesti nimellä "Bill of Materials". Kyseiseen listaan kuuluvat elektroniikkakomponenttien lisäksi myös kaikki muut laitteen rakentamiseen vaadittavat osat, kuten mm. piirilevyt, sekä etupaneelit. "Bill of Materials" on siis kattava, kaikkien komponenttien, osien ja raaka-aineiden lista joita vaaditaan minkä tahansa tuotteen rakentamiseen [(Investopedia - Bill of Materials)](https://www.investopedia.com/terms/b/bill-of-materials.asp)

![bomtools001](./imgs/bomtools001.png)

_KiCadin Bill of Materials työkalu löytyy kytkentäkaavaohjelman ylävalikosta_

![bomtools002](./imgs/bomtools002.png)

_Bill of Materials -työkalun eri vaihtoehtoja listan luomiselle_

Tämän opinnäytetyön projektia varten tavallinen Excel-taulukko toimisi BOM:na. Taulukosta näkyisi kaikkien komponenttien kytkentäkaavassa käytetty viite, komponenttien arvo tai nimi, vaadittu lukumäärä, sekä Mouser verkkokaupan viitenumero kyseiselle komponentille. Niiden komponenttien osalta, joita Mouserin valikoimista ei löydy on ilmoitettu vaihtoehtoisen yrityksen nimi, sekä heidän komponentille käyttämänsä viite.

![bom001.png](./imgs/bom001.png)

_Mouser verkkokaupan ostoskori, sekä KISSe-projektin Bill of Materials_

Projektin laitteen komponentit koottiin aluksi Mouser verkkokaupassa ostoskoriin, jonka jälkeen ostoskori tallennettiin käyttäjän projekteihin. Näin tulevaisuudessa samat komponentit voitaisiin tilata pelkästään projektin viemisellä ostoskoriin. Sarjatuotantovaiheessa voitaisiin tässä kohti ostaa yksi "projekti" useita kertoja, jolloin projektien määrä kerrotaan haluttujen laitteiden määrällä.

![bom002.png](./imgs/bom002.png)

_Ostoskori muutettuna projektiksi_

**x Laitteen rakennus ja laskelmat monistamisesta**

  // Siirrä tänne "**x.3 Monistamisen laskelmat (otsikko työn alla)**", sekä "**x.3 Kokoonpano**" ja yhdistä ne järkeväksi kokonaisuudeksi. Nämä on luontevaa käydä näin opinnäytetyön lopussa, eikä keskellä, sillä kyseessä on prosessin yksi myöhäisimmistä vaiheista.

Mahdollisesti tuotteeksi päätyvän laitteen lopullisen hinnan laskemiseksi tarvittaisiin laskelmat tai tarkat arvioit kaikista laitteen rakennukseen liittyvistä kuluista. Laite vaatii jonkin verran käsin asennusta ja tämän työmäärän rahallinen arvo on aina arvio riippuen siitä, kuinka nopeasti ja millä tuntipalkalla rakentaminen pystytään toteuttamaan. Näistä saaduista laskelmista voidaan laskea suhteellisen tarkka katteeton hinta laitteelle. 

**x.1 Laitteen kokoonpano**

Laitteen kokoonpanossa pintaliitoskomponenttien asennukseen kulunutta aikaa ei olla otettu huomioon. Projektin ajoituksessa ollaan lähdetty oletuksesta, että pintaliitoskomponentit ovat juotettu tehtaalla valmiiksi piirilevyille. Tätä ei kuitenkaan tehty tämän projektin puitteissa komponenttien saatavuuden ja koronarajoitusten aiheuttamien mahdollisten tuotantoviivästyksien takia.

![smd_populated001](./imgs/smd_populated001.png)

_Pintaliitoskomponentit asennettuna piirilevylle_

Käsinasennusta varten piirilevy asetettiin piirilevytelineeseen. Etupaneelia käytettiin apuna lähtöjakkien, enkooderin, segmenttinäyttöjen, sekä potentiometrin asettamiseen paikoilleen. Asennus ajoitettiin puhelimen sekuntikellolla. Kaikki käsin asennettavat komponentit otettiin valmiiksi esille ja järjestettiin asennusjärjestyksen mukaan.

![smd_populated002](./imgs/smd_populated002.png)

_Työpiste ennen asennusta_

Käsin asennus kesti yhteensä 21 minuuttia ja 19 sekuntia. Lopullisissa laskelmissa tämä voidaan pyöristää 20 minuuttiin, sillä asennuksen aikana piirilevytelineen ruuveja jouduttiin jatkuvasti kiristämään laitteen huonon kunnon takia. Laitteesta jäivät asentamatta ICSP-, sekä piikkirimaliittimet Teensy LC:lle. Näiden asentaminen on kuitenkin helppoa ja suoraviivaista, joten niiden puuttuminen ei vaikuta lopulliseen 20 minuutin aikaan.

![pcb_done001](./imgs/pcb_done001.png)

_Valmis laite ilman etupaneelia_

Harjoittelun myötä laiteen asennukseen kuluva aika voisi olla 15 minuuttia. Laitteen rakennukseen kuluva aika voitaisiin jopa puolittaa 10 minuuttiin, jos laitteen käyttämät kytkimet eivät vaatisi läpiladottavien LED-komponenttien käyttöä.

**x.2 Laskelmat laitteen monistamisesta**

Tämän opinnäytetyön projektin aikana on jätetty pois tarkka laitteen ohjelmistokehitykseen kuluva aika, sekä tästä koituvat kustannukset. Projektisuunnitelmassa tämän ajan on kuitenkin arvioitu kustantavan 10 000 euroa. Tämä luku on muodostunut 750 euron teoreettisesta viikkopalkasta, joka on kerrottu 13:sta työviikolla. Tätä lukua ei kuitenkaan tulla suhteuttamaan laitteen rakennuskustannuksiin.

Laitteen rakennuksen kustannuksissa oletetaan yhden työtunnin maksavan 20 euroa. Yhden tunnin aikana pystyisi realistisesti rakentamaan kolme valmista laitetta. Yhden laitteen rakennukseen käytettävä aika tulisi siis maksamaan n. 6,67 euroa. Seuraavaksi kaikkien komponenttien hinta lisättiin laskuihin. Piirilevyjen ja etupaneelien hinta saatiin suoraan aiemmin tehdyn tilauksen tilausvahvistuksesta. Yhden laitteen rakentamisen kokonaiskustannuksiksi saatiin 44,365 euroa.

Seuraavaksi laskettiin sadan laitteen rakennuksen hinta. Sadan laitteen rakennus veisi yhdeltä ihmiseltä n. 33,3 tuntia, joka on vielä realistinen työtaakka yhdelle ihmiselle. Työtunnin hinta pysyi sama kuin aikaisemmissa laskelmissa. Piirilevyjen ja etupaneelien hinta saatiin suoraan JLCPCB:n projektiseurannasta. Komponenttimäärien satakertaistuminen voisi kuitenkin johtaa huomattaviin säästöihin, sillä useat komponenttijakelijat tarjoavat kappalehintoihin alennuksia tilausmäärän mukaan. 

Työtuntien hinnaksi sadan laitteen kohdalla tuli 666,67 euroa, johon lisättiin kaikkien komponenttien hinta. Sadan laitteen rakennus maksaisi yhteensä 2678,57 euroa. Yhden laitteen hinnaksi tulisi tällöin 29,4841 euroa. Yhden laitteen hinta sadan laitteen joukosta olisi tällöin noin 66,45% yhden laitteen hinnasta, jos sitä tilattaisiin ja rakennettaisiin vain yksi kappale.

![calcs001](./imgs/calcs001.png)

_Laskelmia laitteen monistamisesta_

**x Tulokset ja retrospektio**

  // Tässä käydään läpi opinnäytetyön tuloksia, katsotaan onnistumiset, epäonnistumiset ja arvioidaan tulosten vaikuttavuus.

## Lähteet

Arduino a. What is Arduino?. Luettavissa: https://www.arduino.cc/en/Guide/Introduction. Luettu 26.4.2021.

Arduino b. Shields. Luettavissa: https://www.arduino.cc/en/Main/arduinoShields. Luettu 26.4.2021.

PJRC. Teensy® USB Development Board. Luettavissa: https://www.pjrc.com/teensy/. Luettu 26.4.2021.

Leonora Tindall 2020. Modular Synthesis and UNIX. Luettavissa: https://nora.codes/post/modular-synthesis-and-unix/. Luettu 26.4.2021

Reverb 2020. Beginner's Guide to Eurorack: Case Basics, Power Supplies, and Your First Modules. Luettavissa: https://reverb.com/news/beginners-guide-to-eurorack-case-basics-oscillators-filters. Luettu 26.4.2021.

Doepfer a. A-100 Construction Details. Luettavissa: http://www.doepfer.de/a100_man/a100m_e.htm. Luettu 26.4.2021.

Doepfer b. A-100 Construction Details. Luettavissa: http://www.doepfer.de/a100_man/a100t_e.htm. Luettu 26.4.2021.

Chris Meyer 2016. 1 v/oct. Learning Modular. Luettavissa: https://learningmodular.com/glossary/1-voct/. Luettu 26.4.2021. /*Korjaa tämä myöhemmin, selvitä miten merkitään, kun ilmoitettu "julkaisija", sekä tekijä*/

Elicia White 2011. Making Embedded Systems. O'Reilly Media. Luettavissa: https://www.oreilly.com/library/view/making-embedded-systems/9781449308889/. Luettu 26.4.2021.

Karppila, A. 2014. Arduino-pohjainen laite liikkeen ja lämpötilan monitorointiin. Haaga-Helia ammattikorkeakoulu, Tietojenkäsittelyn
koulutusohjelma. Luettavissa: https://www.theseus.fi/handle/10024/81790. Luettu 26.4.2021.

PlatformIO. What is PlatformIO?. Luettavissa: https://docs.platformio.org/en/latest/what-is-platformio.html. Luettu 26.4.2021.

Microchip. MCP23017/MCP23S17. Luettavissa: https://ww1.microchip.com/downloads/en/devicedoc/20001952c.pdf. Luettu 26.4.2021.

Mitchell Grant 2020. Bill of Materials (BOM). Investopedia. Luettavissa: https://www.investopedia.com/terms/b/bill-of-materials.asp. Luettu 26.4.2021.

/* X. Kai, C. C., & Fai, L. K. (1997). Rapid Prototyping. _Nanyang technological university_. */

// Yllä oleva kadonnut internetistä? Katso joku vastaava, korjaa luku 2.3.

