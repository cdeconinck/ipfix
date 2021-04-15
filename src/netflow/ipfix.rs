use core::convert::TryInto;
use log::debug;
use num_traits::FromPrimitive;
use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::netflow::NetflowMsg;

pub const VERSION: u16 = 10;

/******************************** MSG HEADER ********************************/

/// from https://tools.ietf.org/html/rfc7011
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       Version Number          |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Export Time                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Sequence Number                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Observation Domain ID                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```

#[derive(Debug)]
pub struct Header {
    pub version: u16,     // Version of IPFIX to which this Message conforms
    pub length: u16,      // Total length of the IPFIX Message, measured in octets, including Message Header and Set(s).
    pub export_time: u32, // Time at which the IPFIX Message Header leaves the Exporter expressed in seconds since the UNIX epoch
    pub seq_number: u32,  // Incremental sequence counter modulo 2^32 of all IPFIX Data Record sent in the current stream from the current Observation Domain by the Exporting Process.
    pub domain_id: u32,   // Identifier used to uniquely identify to the Collecting Process the Observation Domain that metered the Flows
}

impl Header {
    pub const SIZE: usize = std::mem::size_of::<Header>();

    pub fn read(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < Self::SIZE {
            return Err(format!("Not enoutgh space in buffer to read the IPFIX HEADER_SIZE, required {} but received {}", Self::SIZE, buf.len()));
        }

        Ok(Header {
            version: u16::from_be_bytes(buf[0..2].try_into().unwrap()),
            length: u16::from_be_bytes(buf[2..4].try_into().unwrap()),
            export_time: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
            seq_number: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            domain_id: u32::from_be_bytes(buf[12..16].try_into().unwrap()),
        })
    }
}

/******************************** SET HEADER ********************************/

pub const TEMPATE_SET_ID: u16 = 2;
pub const OPTION_TEMPATE_SET_ID: u16 = 3;
pub const DATA_SET_ID_MIN: u16 = 256;

/// from https://tools.ietf.org/html/rfc7011
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Set ID               |          Length               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```

#[derive(Debug)]
pub struct SetHeader {
    pub id: u16,     // Identifies the Set.
    pub length: u16, // Total length of the Set, in octets, including the Set Header, all records, and the optional padding
}

impl SetHeader {
    pub const SIZE: usize = std::mem::size_of::<SetHeader>();

    pub fn read(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < Self::SIZE {
            return Err(format!("Not enough space in buffer to read IPFIX SetHeader, required {} but received {}", Self::SIZE, buf.len()));
        }

        Ok(SetHeader {
            id: u16::from_be_bytes(buf[0..2].try_into().unwrap()),
            length: u16::from_be_bytes(buf[2..4].try_into().unwrap()),
        })
    }

    #[inline]
    pub fn content_size(&self) -> usize {
        self.length as usize - Self::SIZE
    }
}

/******************************** TEMPLATE HEADER ********************************/

/// from https://tools.ietf.org/html/rfc7011
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Template ID (> 255)      |         Field Count           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```

#[derive(Debug)]
pub struct TemplateHeader {
    pub id: u16,          // Each Template Record is given a unique Template ID in the range 256 to 65535
    pub field_count: u16, // Number of fields in this Template Record.
}

impl TemplateHeader {
    pub const SIZE: usize = 4;

    pub fn read(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < Self::SIZE {
            return Err(format!("Not enough space in buffer to read IPFIX TemplateHeader, required {} but received {}", Self::SIZE, buf.len()));
        }

        Ok(TemplateHeader {
            id: u16::from_be_bytes(buf[0..2].try_into().unwrap()),
            field_count: u16::from_be_bytes(buf[2..4].try_into().unwrap()),
        })
    }
}

/********************************  TEMPLATE RECORD FIELD ********************************/

/// from https://tools.ietf.org/html/rfc7011
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Field id             |         Field Length          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```

#[derive(Debug)]
pub struct TemplateField {
    pub id: FieldType, // A numeric value that represents the Information Element
    pub length: u16,   // The length of the corresponding encoded Information Element, in octets
}

impl TemplateField {
    pub const SIZE: usize = 4;

    pub fn read(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < Self::SIZE {
            return Err(format!("Not enough space in buffer to read IPFIX TemplateField, required {} but received {}", Self::SIZE, buf.len()));
        }

        let id_num = u16::from_be_bytes(buf[0..2].try_into().unwrap());

        Ok(TemplateField {
            id: match FromPrimitive::from_u16(id_num) {
                Some(id) => id,
                None => return Err(format!("No FieldType found for value : {}", id_num)),
            },
            length: u16::from_be_bytes(buf[2..4].try_into().unwrap()),
        })
    }
}

/********************************  DATA SET ********************************/

#[derive(Debug, Default)]
pub struct DataSet {
    pub fields: HashMap<FieldType, FieldValue>,
}

#[rustfmt::skip]
impl DataSet {
    pub fn read_from_option_template(buf: &[u8], template: &OptionTemplate) -> Self {
        DataSet::parse_field(buf, &template.fields)
    }

    pub fn read_from_template (buf: &[u8], template: &Template) -> Self {
        DataSet::parse_field(buf, &template.fields)
    }

    fn parse_field(buf: &[u8], field_list: &Vec<TemplateField>) -> Self {
        let mut set: DataSet = DataSet { fields: HashMap::with_capacity(field_list.len()) };
        let mut offset = 0;

        for field in field_list {
            match field.id {
                FieldType::SOURCEIPV6ADDRESS | 
                FieldType::DESTINATIONIPV6ADDRESS |
                FieldType::EXPORTERIPV6ADDRESS  => {
                    set.fields.insert(field.id, FieldValue::IPv6(u128::from_be_bytes(buf[offset..offset + 16].try_into().unwrap())));
                }
                FieldType::SOURCEIPV4ADDRESS | 
                FieldType::DESTINATIONIPV4ADDRESS |
                FieldType::EXPORTERIPV4ADDRESS => {
                    set.fields.insert(field.id, FieldValue::IPv4(u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap())));
                }
                FieldType::FLOWSTARTMILLISECONDS | 
                FieldType::FLOWENDMILLISECONDS |
                FieldType::SYSTEMINITTIMEMILLISECONDS |
                FieldType::EXPORTEDFLOWRECORDTOTALCOUNT |
                FieldType::EXPORTEDMESSAGETOTALCOUNT => {
                    set.fields.insert(field.id, FieldValue::U64(u64::from_be_bytes(buf[offset..offset + 8].try_into().unwrap())));
                }
                FieldType::OCTETDELTACOUNT | 
                FieldType::PACKETDELTACOUNT |
                FieldType::EXPORTINGPROCESSID |
                FieldType::SAMPLINGINTERVAL => {
                    set.fields.insert(field.id, FieldValue::U32(u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap())));
                }
                FieldType::SOURCETRANSPORTPORT |
                FieldType::DESTINATIONTRANSPORTPORT | 
                FieldType::INGRESSINTERFACE | 
                FieldType::EGRESSINTERFACE|
                FieldType::VLANID => {
                    set.fields.insert(field.id, FieldValue::U16(u16::from_be_bytes(buf[offset..offset + 2].try_into().unwrap())));
                }
                FieldType::PROTOCOLIDENTIFIER | 
                FieldType::FLOWENDREASON | 
                FieldType::IPCLASSOFSERVICE| 
                FieldType::SOURCEIPV4PREFIXLENGTH |
                FieldType::DESTINATIONIPV4PREFIXLENGTH | 
                FieldType::EXPORTTRANSPORTPROTOCOL | 
                FieldType::EXPORTPROTOCOLVERSION => {
                    set.fields.insert(field.id, FieldValue::U8(buf[offset]));
                }
                _ => {
                    debug!("Skipping field {:?} with size {}", field.id, field.length);
                }
            }

            offset += field.length as usize;
        }

        set
    }
}

impl NetflowMsg for DataSet {}

impl fmt::Display for DataSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (ftype, fvalue) in self.fields.iter() {
            write!(f, "{:?}: {}, ", ftype, fvalue)?;
        }

        Ok(())
    }
}

/********************************  OPTION TEMPLATE HEADER ********************************/

/// from https://tools.ietf.org/html/rfc7011
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Template ID (> 255)   |         Field Count           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Scope Field Count        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```

#[derive(Debug)]
pub struct OptionTemplateHeader {
    pub id: u16,                // Options Template id in the range 256 to 65535
    pub field_count: u16,       // Number of all fields in this Options Template Record, including the Scope Fields
    pub scope_field_count: u16, // Number of scope fields in this Options Template Record
}

impl OptionTemplateHeader {
    pub const SIZE: usize = 6;

    pub fn read(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < Self::SIZE {
            return Err(format!(
                "Not enough space in buffer to read IPFIX OptionTemplateHeader, required {} but received {}",
                Self::SIZE,
                buf.len()
            ));
        }

        Ok(OptionTemplateHeader {
            id: u16::from_be_bytes(buf[0..2].try_into().unwrap()),
            field_count: u16::from_be_bytes(buf[2..4].try_into().unwrap()),
            scope_field_count: u16::from_be_bytes(buf[4..6].try_into().unwrap()),
        })
    }
}

/********************************  TEMPLATE ********************************/

pub struct Template {
    pub header: TemplateHeader,
    pub fields: Vec<TemplateField>,
}

impl Template {
    pub fn read(buf: &[u8]) -> Result<Self, String> {
        let header = TemplateHeader::read(&buf)?;
        let mut fields: Vec<TemplateField> = vec![];
        let mut offset = TemplateHeader::SIZE;

        for _ in 0..header.field_count {
            fields.push(TemplateField::read(&buf[offset..])?);
            offset += TemplateField::SIZE;
        }

        Ok(Template { header, fields })
    }
}

impl fmt::Display for Template {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", &self.header)?;

        for field in &self.fields {
            write!(f, "\n\t{:?}", field)?;
        }

        Ok(())
    }
}

/********************************  OPTION TEMPLATE ********************************/

pub struct OptionTemplate {
    pub header: OptionTemplateHeader,
    pub fields: Vec<TemplateField>,
}

impl OptionTemplate {
    pub fn read(buf: &[u8]) -> Result<Self, String> {
        let header = OptionTemplateHeader::read(&buf)?;
        let mut fields: Vec<TemplateField> = vec![];
        let mut offset = OptionTemplateHeader::SIZE;

        for _ in 0..header.field_count {
            fields.push(TemplateField::read(&buf[offset..])?);
            offset += TemplateField::SIZE;
        }

        Ok(OptionTemplate { header, fields })
    }
}

impl fmt::Display for OptionTemplate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", &self.header)?;

        for field in &self.fields {
            write!(f, "\n\t{:?}", field)?;
        }

        Ok(())
    }
}

/********************************  IPFIX FIELD TYPE ********************************/

/// from http://www.iana.org/assignments/ipfix/ipfix.xml
#[derive(FromPrimitive, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Copy, Clone)]
#[repr(u16)]
pub enum FieldType {
    RESERVED = 0,
    OCTETDELTACOUNT = 1,
    PACKETDELTACOUNT = 2,
    DELTAFLOWCOUNT = 3,
    PROTOCOLIDENTIFIER = 4,
    IPCLASSOFSERVICE = 5,
    TCPCONTROLBITS = 6,
    SOURCETRANSPORTPORT = 7,
    SOURCEIPV4ADDRESS = 8,
    SOURCEIPV4PREFIXLENGTH = 9,
    INGRESSINTERFACE = 10,
    DESTINATIONTRANSPORTPORT = 11,
    DESTINATIONIPV4ADDRESS = 12,
    DESTINATIONIPV4PREFIXLENGTH = 13,
    EGRESSINTERFACE = 14,
    IPNEXTHOPIPV4ADDRESS = 15,
    BGPSOURCEASNUMBER = 16,
    BGPDESTINATIONASNUMBER = 17,
    BGPNEXTHOPIPV4ADDRESS = 18,
    POSTMCASTPACKETDELTACOUNT = 19,
    POSTMCASTOCTETDELTACOUNT = 20,
    FLOWENDSYSUPTIME = 21,
    FLOWSTARTSYSUPTIME = 22,
    POSTOCTETDELTACOUNT = 23,
    POSTPACKETDELTACOUNT = 24,
    MINIMUMIPTOTALLENGTH = 25,
    MAXIMUMIPTOTALLENGTH = 26,
    SOURCEIPV6ADDRESS = 27,
    DESTINATIONIPV6ADDRESS = 28,
    SOURCEIPV6PREFIXLENGTH = 29,
    DESTINATIONIPV6PREFIXLENGTH = 30,
    FLOWLABELIPV6 = 31,
    ICMPTYPECODEIPV4 = 32,
    IGMPTYPE = 33,
    SAMPLINGINTERVAL = 34,
    SAMPLINGALGORITHM = 35,
    FLOWACTIVETIMEOUT = 36,
    FLOWIDLETIMEOUT = 37,
    ENGINETYPE = 38,
    ENGINEID = 39,
    EXPORTEDOCTETTOTALCOUNT = 40,
    EXPORTEDMESSAGETOTALCOUNT = 41,
    EXPORTEDFLOWRECORDTOTALCOUNT = 42,
    IPV4ROUTERSC = 43,
    SOURCEIPV4PREFIX = 44,
    DESTINATIONIPV4PREFIX = 45,
    MPLSTOPLABELTYPE = 46,
    MPLSTOPLABELIPV4ADDRESS = 47,
    SAMPLERID = 48,
    SAMPLERMODE = 49,
    SAMPLERRANDOMINTERVAL = 50,
    CLASSID = 51,
    MINIMUMTTL = 52,
    MAXIMUMTTL = 53,
    FRAGMENTIDENTIFICATION = 54,
    POSTIPCLASSOFSERVICE = 55,
    SOURCEMACADDRESS = 56,
    POSTDESTINATIONMACADDRESS = 57,
    VLANID = 58,
    POSTVLANID = 59,
    IPVERSION = 60,
    FLOWDIRECTION = 61,
    IPNEXTHOPIPV6ADDRESS = 62,
    BGPNEXTHOPIPV6ADDRESS = 63,
    IPV6EXTENSIONHEADERS = 64,
    MPLSTOPLABELSTACKSECTION = 70,
    MPLSLABELSTACKSECTION2 = 71,
    MPLSLABELSTACKSECTION3 = 72,
    MPLSLABELSTACKSECTION4 = 73,
    MPLSLABELSTACKSECTION5 = 74,
    MPLSLABELSTACKSECTION6 = 75,
    MPLSLABELSTACKSECTION7 = 76,
    MPLSLABELSTACKSECTION8 = 77,
    MPLSLABELSTACKSECTION9 = 78,
    MPLSLABELSTACKSECTION10 = 79,
    DESTINATIONMACADDRESS = 80,
    POSTSOURCEMACADDRESS = 81,
    INTERFACENAME = 82,
    INTERFACEDESCRIPTION = 83,
    SAMPLERNAME = 84,
    OCTETTOTALCOUNT = 85,
    PACKETTOTALCOUNT = 86,
    FLAGSANDSAMPLERID = 87,
    FRAGMENTOFFSET = 88,
    FORWARDINGSTATUS = 89,
    MPLSVPNROUTEDISTINGUISHER = 90,
    MPLSTOPLABELPREFIXLENGTH = 91,
    SRCTRAFFICINDEX = 92,
    DSTTRAFFICINDEX = 93,
    APPLICATIONDESCRIPTION = 94,
    APPLICATIONID = 95,
    APPLICATIONNAME = 96,
    POSTIPDIFFSERVCODEPOINT = 98,
    MULTICASTREPLICATIONFACTOR = 99,
    CLASSNAME = 100,
    CLASSIFICATIONENGINEID = 101,
    LAYER2PACKETSECTIONOFFSET = 102,
    LAYER2PACKETSECTIONSIZE = 103,
    LAYER2PACKETSECTIONDATA = 104,
    BGPNEXTADJACENTASNUMBER = 128,
    BGPPREVADJACENTASNUMBER = 129,
    EXPORTERIPV4ADDRESS = 130,
    EXPORTERIPV6ADDRESS = 131,
    DROPPEDOCTETDELTACOUNT = 132,
    DROPPEDPACKETDELTACOUNT = 133,
    DROPPEDOCTETTOTALCOUNT = 134,
    DROPPEDPACKETTOTALCOUNT = 135,
    FLOWENDREASON = 136,
    COMMONPROPERTIESID = 137,
    OBSERVATIONPOINTID = 138,
    ICMPTYPECODEIPV6 = 139,
    MPLSTOPLABELIPV6ADDRESS = 140,
    LINECARDID = 141,
    PORTID = 142,
    METERINGPROCESSID = 143,
    EXPORTINGPROCESSID = 144,
    TEMPLATEID = 145,
    WLANCHANNELID = 146,
    WLANSSID = 147,
    FLOWID = 148,
    OBSERVATIONDOMAINID = 149,
    FLOWSTARTSECONDS = 150,
    FLOWENDSECONDS = 151,
    FLOWSTARTMILLISECONDS = 152,
    FLOWENDMILLISECONDS = 153,
    FLOWSTARTMICROSECONDS = 154,
    FLOWENDMICROSECONDS = 155,
    FLOWSTARTNANOSECONDS = 156,
    FLOWENDNANOSECONDS = 157,
    FLOWSTARTDELTAMICROSECONDS = 158,
    FLOWENDDELTAMICROSECONDS = 159,
    SYSTEMINITTIMEMILLISECONDS = 160,
    FLOWDURATIONMILLISECONDS = 161,
    FLOWDURATIONMICROSECONDS = 162,
    OBSERVEDFLOWTOTALCOUNT = 163,
    IGNOREDPACKETTOTALCOUNT = 164,
    IGNOREDOCTETTOTALCOUNT = 165,
    NOTSENTFLOWTOTALCOUNT = 166,
    NOTSENTPACKETTOTALCOUNT = 167,
    NOTSENTOCTETTOTALCOUNT = 168,
    DESTINATIONIPV6PREFIX = 169,
    SOURCEIPV6PREFIX = 170,
    POSTOCTETTOTALCOUNT = 171,
    POSTPACKETTOTALCOUNT = 172,
    FLOWKEYINDICATOR = 173,
    POSTMCASTPACKETTOTALCOUNT = 174,
    POSTMCASTOCTETTOTALCOUNT = 175,
    ICMPTYPEIPV4 = 176,
    ICMPCODEIPV4 = 177,
    ICMPTYPEIPV6 = 178,
    ICMPCODEIPV6 = 179,
    UDPSOURCEPORT = 180,
    UDPDESTINATIONPORT = 181,
    TCPSOURCEPORT = 182,
    TCPDESTINATIONPORT = 183,
    TCPSEQUENCENUMBER = 184,
    TCPACKNOWLEDGEMENTNUMBER = 185,
    TCPWINDOWSIZE = 186,
    TCPURGENTPOINTER = 187,
    TCPHEADERLENGTH = 188,
    IPHEADERLENGTH = 189,
    TOTALLENGTHIPV4 = 190,
    PAYLOADLENGTHIPV6 = 191,
    IPTTL = 192,
    NEXTHEADERIPV6 = 193,
    MPLSPAYLOADLENGTH = 194,
    IPDIFFSERVCODEPOINT = 195,
    IPPRECEDENCE = 196,
    FRAGMENTFLAGS = 197,
    OCTETDELTASUMOFSQUARES = 198,
    OCTETTOTALSUMOFSQUARES = 199,
    MPLSTOPLABELTTL = 200,
    MPLSLABELSTACKLENGTH = 201,
    MPLSLABELSTACKDEPTH = 202,
    MPLSTOPLABELEXP = 203,
    IPPAYLOADLENGTH = 204,
    UDPMESSAGELENGTH = 205,
    ISMULTICAST = 206,
    IPV4IHL = 207,
    IPV4OPTIONS = 208,
    TCPOPTIONS = 209,
    PADDINGOCTETS = 210,
    COLLECTORIPV4ADDRESS = 211,
    COLLECTORIPV6ADDRESS = 212,
    EXPORTINTERFACE = 213,
    EXPORTPROTOCOLVERSION = 214,
    EXPORTTRANSPORTPROTOCOL = 215,
    COLLECTORTRANSPORTPORT = 216,
    EXPORTERTRANSPORTPORT = 217,
    TCPSYNTOTALCOUNT = 218,
    TCPFINTOTALCOUNT = 219,
    TCPRSTTOTALCOUNT = 220,
    TCPPSHTOTALCOUNT = 221,
    TCPACKTOTALCOUNT = 222,
    TCPURGTOTALCOUNT = 223,
    IPTOTALLENGTH = 224,
    POSTNATSOURCEIPV4ADDRESS = 225,
    POSTNATDESTINATIONIPV4ADDRESS = 226,
    POSTNAPTSOURCETRANSPORTPORT = 227,
    POSTNAPTDESTINATIONTRANSPORTPORT = 228,
    NATORIGINATINGADDRESSREALM = 229,
    NATEVENT = 230,
    INITIATOROCTETS = 231,
    RESPONDEROCTETS = 232,
    FIREWALLEVENT = 233,
    INGRESSVRFID = 234,
    EGRESSVRFID = 235,
    VRFNAME = 236,
    POSTMPLSTOPLABELEXP = 237,
    TCPWINDOWSCALE = 238,
    BIFLOWDIRECTION = 239,
    ETHERNETHEADERLENGTH = 240,
    ETHERNETPAYLOADLENGTH = 241,
    ETHERNETTOTALLENGTH = 242,
    DOT1QVLANID = 243,
    DOT1QPRIORITY = 244,
    DOT1QCUSTOMERVLANID = 245,
    DOT1QCUSTOMERPRIORITY = 246,
    METROEVCID = 247,
    METROEVCTYPE = 248,
    PSEUDOWIREID = 249,
    PSEUDOWIRETYPE = 250,
    PSEUDOWIRECONTROLWORD = 251,
    INGRESSPHYSICALINTERFACE = 252,
    EGRESSPHYSICALINTERFACE = 253,
    POSTDOT1QVLANID = 254,
    POSTDOT1QCUSTOMERVLANID = 255,
    ETHERNETTYPE = 256,
    POSTIPPRECEDENCE = 257,
    COLLECTIONTIMEMILLISECONDS = 258,
    EXPORTSCTPSTREAMID = 259,
    MAXEXPORTSECONDS = 260,
    MAXFLOWENDSECONDS = 261,
    MESSAGEMD5CHECKSUM = 262,
    MESSAGESCOPE = 263,
    MINEXPORTSECONDS = 264,
    MINFLOWSTARTSECONDS = 265,
    OPAQUEOCTETS = 266,
    SESSIONSCOPE = 267,
    MAXFLOWENDMICROSECONDS = 268,
    MAXFLOWENDMILLISECONDS = 269,
    MAXFLOWENDNANOSECONDS = 270,
    MINFLOWSTARTMICROSECONDS = 271,
    MINFLOWSTARTMILLISECONDS = 272,
    MINFLOWSTARTNANOSECONDS = 273,
    COLLECTORCERTIFICATE = 274,
    EXPORTERCERTIFICATE = 275,
    DATARECORDSRELIABILITY = 276,
    OBSERVATIONPOINTTYPE = 277,
    NEWCONNECTIONDELTACOUNT = 278,
    CONNECTIONSUMDURATIONSECONDS = 279,
    CONNECTIONTRANSACTIONID = 280,
    POSTNATSOURCEIPV6ADDRESS = 281,
    POSTNATDESTINATIONIPV6ADDRESS = 282,
    NATPOOLID = 283,
    NATPOOLNAME = 284,
    ANONYMIZATIONFLAGS = 285,
    ANONYMIZATIONTECHNIQUE = 286,
    INFORMATIONELEMENTINDEX = 287,
    P2PTECHNOLOGY = 288,
    TUNNELTECHNOLOGY = 289,
    ENCRYPTEDTECHNOLOGY = 290,
    BASICLIST = 291,
    SUBTEMPLATELIST = 292,
    SUBTEMPLATEMULTILIST = 293,
    BGPVALIDITYSTATE = 294,
    IPSECSPI = 295,
    GREKEY = 296,
    NATTYPE = 297,
    INITIATORPACKETS = 298,
    RESPONDERPACKETS = 299,
    OBSERVATIONDOMAINNAME = 300,
    SELECTIONSEQUENCEID = 301,
    SELECTORID = 302,
    INFORMATIONELEMENTID = 303,
    SELECTORALGORITHM = 304,
    SAMPLINGPACKETINTERVAL = 305,
    SAMPLINGPACKETSPACE = 306,
    SAMPLINGTIMEINTERVAL = 307,
    SAMPLINGTIMESPACE = 308,
    SAMPLINGSIZE = 309,
    SAMPLINGPOPULATION = 310,
    SAMPLINGPROBABILITY = 311,
    DATALINKFRAMESIZE = 312,
    IPHEADERPACKETSECTION = 313,
    IPPAYLOADPACKETSECTION = 314,
    DATALINKFRAMESECTION = 315,
    MPLSLABELSTACKSECTION = 316,
    MPLSPAYLOADPACKETSECTION = 317,
    SELECTORIDTOTALPKTSOBSERVED = 318,
    SELECTORIDTOTALPKTSSELECTED = 319,
    ABSOLUTEERROR = 320,
    RELATIVEERROR = 321,
    OBSERVATIONTIMESECONDS = 322,
    OBSERVATIONTIMEMILLISECONDS = 323,
    OBSERVATIONTIMEMICROSECONDS = 324,
    OBSERVATIONTIMENANOSECONDS = 325,
    DIGESTHASHVALUE = 326,
    HASHIPPAYLOADOFFSET = 327,
    HASHIPPAYLOADSIZE = 328,
    HASHOUTPUTRANGEMIN = 329,
    HASHOUTPUTRANGEMAX = 330,
    HASHSELECTEDRANGEMIN = 331,
    HASHSELECTEDRANGEMAX = 332,
    HASHDIGESTOUTPUT = 333,
    HASHINITIALISERVALUE = 334,
    SELECTORNAME = 335,
    UPPERCILIMIT = 336,
    LOWERCILIMIT = 337,
    CONFIDENCELEVEL = 338,
    INFORMATIONELEMENTDATATYPE = 339,
    INFORMATIONELEMENTDESCRIPTION = 340,
    INFORMATIONELEMENTNAME = 341,
    INFORMATIONELEMENTRANGEBEGIN = 342,
    INFORMATIONELEMENTRANGEEND = 343,
    INFORMATIONELEMENTSEMANTICS = 344,
    INFORMATIONELEMENTUNITS = 345,
    PRIVATEENTERPRISENUMBER = 346,
    VIRTUALSTATIONINTERFACEID = 347,
    VIRTUALSTATIONINTERFACENAME = 348,
    VIRTUALSTATIONUUID = 349,
    VIRTUALSTATIONNAME = 350,
    LAYER2SEGMENTID = 351,
    LAYER2OCTETDELTACOUNT = 352,
    LAYER2OCTETTOTALCOUNT = 353,
    INGRESSUNICASTPACKETTOTALCOUNT = 354,
    INGRESSMULTICASTPACKETTOTALCOUNT = 355,
    INGRESSBROADCASTPACKETTOTALCOUNT = 356,
    EGRESSUNICASTPACKETTOTALCOUNT = 357,
    EGRESSBROADCASTPACKETTOTALCOUNT = 358,
    MONITORINGINTERVALSTARTMILLISECONDS = 359,
    MONITORINGINTERVALENDMILLISECONDS = 360,
    PORTRANGESTART = 361,
    PORTRANGEEND = 362,
    PORTRANGESTEPSIZE = 363,
    PORTRANGENUMPORTS = 364,
    STAMACADDRESS = 365,
    STAIPV4ADDRESS = 366,
    WTPMACADDRESS = 367,
    INGRESSINTERFACETYPE = 368,
    EGRESSINTERFACETYPE = 369,
    RTPSEQUENCENUMBER = 370,
    USERNAME = 371,
    APPLICATIONCATEGORYNAME = 372,
    APPLICATIONSUBCATEGORYNAME = 373,
    APPLICATIONGROUPNAME = 374,
    ORIGINALFLOWSPRESENT = 375,
    ORIGINALFLOWSINITIATED = 376,
    ORIGINALFLOWSCOMPLETED = 377,
    DISTINCTCOUNTOFSOURCEIPADDRESS = 378,
    DISTINCTCOUNTOFDESTINATIONIPADDRESS = 379,
    DISTINCTCOUNTOFSOURCEIPV4ADDRESS = 380,
    DISTINCTCOUNTOFDESTINATIONIPV4ADDRESS = 381,
    DISTINCTCOUNTOFSOURCEIPV6ADDRESS = 382,
    DISTINCTCOUNTOFDESTINATIONIPV6ADDRESS = 383,
    VALUEDISTRIBUTIONMETHOD = 384,
    RFC3550JITTERMILLISECONDS = 385,
    RFC3550JITTERMICROSECONDS = 386,
    RFC3550JITTERNANOSECONDS = 387,
    DOT1QDEI = 388,
    DOT1QCUSTOMERDEI = 389,
    FLOWSELECTORALGORITHM = 390,
    FLOWSELECTEDOCTETDELTACOUNT = 391,
    FLOWSELECTEDPACKETDELTACOUNT = 392,
    FLOWSELECTEDFLOWDELTACOUNT = 393,
    SELECTORIDTOTALFLOWSOBSERVED = 394,
    SELECTORIDTOTALFLOWSSELECTED = 395,
    SAMPLINGFLOWINTERVAL = 396,
    SAMPLINGFLOWSPACING = 397,
    FLOWSAMPLINGTIMEINTERVAL = 398,
    FLOWSAMPLINGTIMESPACING = 399,
    HASHFLOWDOMAIN = 400,
    TRANSPORTOCTETDELTACOUNT = 401,
    TRANSPORTPACKETDELTACOUNT = 402,
    ORIGINALEXPORTERIPV4ADDRESS = 403,
    ORIGINALEXPORTERIPV6ADDRESS = 404,
    ORIGINALOBSERVATIONDOMAINID = 405,
    INTERMEDIATEPROCESSID = 406,
    IGNOREDDATARECORDTOTALCOUNT = 407,
    DATALINKFRAMETYPE = 408,
    SECTIONOFFSET = 409,
    SECTIONEXPORTEDOCTETS = 410,
    DOT1QSERVICEINSTANCETAG = 411,
    DOT1QSERVICEINSTANCEID = 412,
    DOT1QSERVICEINSTANCEPRIORITY = 413,
    DOT1QCUSTOMERSOURCEMACADDRESS = 414,
    DOT1QCUSTOMERDESTINATIONMACADDRESS = 415,
    POSTLAYER2OCTETDELTACOUNT = 417,
    POSTMCASTLAYER2OCTETDELTACOUNT = 418,
    POSTLAYER2OCTETTOTALCOUNT = 420,
    POSTMCASTLAYER2OCTETTOTALCOUNT = 421,
    MINIMUMLAYER2TOTALLENGTH = 422,
    MAXIMUMLAYER2TOTALLENGTH = 423,
    DROPPEDLAYER2OCTETDELTACOUNT = 424,
    DROPPEDLAYER2OCTETTOTALCOUNT = 425,
    IGNOREDLAYER2OCTETTOTALCOUNT = 426,
    NOTSENTLAYER2OCTETTOTALCOUNT = 427,
    LAYER2OCTETDELTASUMOFSQUARES = 428,
    LAYER2OCTETTOTALSUMOFSQUARES = 429,
    LAYER2FRAMEDELTACOUNT = 430,
    LAYER2FRAMETOTALCOUNT = 431,
    PSEUDOWIREDESTINATIONIPV4ADDRESS = 432,
    IGNOREDLAYER2FRAMETOTALCOUNT = 433,
    // add other fields here...
}

/******************************** IPFIX FIELD VALUE ********************************/

/// from http://www.iana.org/assignments/ipfix/ipfix.xml
#[derive(Debug)]
pub enum FieldValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    IPv4(u32),
    IPv6(u128),
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FieldValue::U8(v) => v.fmt(f),
            FieldValue::U16(v) => v.fmt(f),
            FieldValue::U32(v) => v.fmt(f),
            FieldValue::U64(v) => v.fmt(f),
            FieldValue::IPv4(v) => Ipv4Addr::from(*v).fmt(f),
            FieldValue::IPv6(v) => Ipv6Addr::from(*v).fmt(f),
        }
    }
}

/******************************** IPFIX END REASON ********************************/

/// from http://www.iana.org/assignments/ipfix/ipfix.xml
#[derive(FromPrimitive, PartialEq, Debug)]
#[repr(u8)]
pub enum EndReason {
    IDLETIMEOUT = 1,
    ACTIVETIMEOUT = 2,
    ENDOFFLOWDETECTED = 3,
    FORCEDEND = 4,
    LACKOFRESOURCES = 5,
}
