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
    pub const SIZE: usize = 16;

    pub fn read(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < Self::SIZE {
            return Err(format!("Not enough space in buffer to read the IPFIX HEADER_SIZE, required {} but received {}", Self::SIZE, buf.len()));
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
    pub const SIZE: usize = 4;

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
    pub const MIN_SET_ID: u16 = 256;

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
                FieldType::SourceIPv6Address | 
                FieldType::DestinationIPv6Address |
                FieldType::ExporterIPv6Address  => {
                    set.fields.insert(field.id, FieldValue::IPv6(u128::from_be_bytes(buf[offset..offset + 16].try_into().unwrap())));
                }
                FieldType::SourceIPv4Address | 
                FieldType::DestinationIPv4Address |
                FieldType::ExporterIPv4Address => {
                    set.fields.insert(field.id, FieldValue::IPv4(u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap())));
                }
                FieldType::FlowStartMilliseconds | 
                FieldType::FlowEndMilliseconds |
                FieldType::SystemInitTimeMilliseconds |
                FieldType::ExportedFlowRecordTotalCount |
                FieldType::ExportedMessageTotalCount => {
                    set.fields.insert(field.id, FieldValue::U64(u64::from_be_bytes(buf[offset..offset + 8].try_into().unwrap())));
                }
                FieldType::OctetDeltaCount | 
                FieldType::PacketDeltaCount |
                FieldType::ExportingProcessId |
                FieldType::SamplingInterval => {
                    set.fields.insert(field.id, FieldValue::U32(u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap())));
                }
                FieldType::SourceTransportPort |
                FieldType::DestinationTransportPort | 
                FieldType::IngressInterface | 
                FieldType::EgressInterface|
                FieldType::VlanId => {
                    set.fields.insert(field.id, FieldValue::U16(u16::from_be_bytes(buf[offset..offset + 2].try_into().unwrap())));
                }
                FieldType::ProtocolIdentifier | 
                FieldType::FlowEndReason | 
                FieldType::IPClassOfService| 
                FieldType::SourceIPv4PrefixLength |
                FieldType::DestinationIPv4PrefixLength | 
                FieldType::ExportTransportProtocol | 
                FieldType::ExportProtocolVersion => {
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
    pub const SET_ID: u16 = 2;

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
    pub const SET_ID: u16 = 3;

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
    Reserved = 0,
    OctetDeltaCount = 1,
    PacketDeltaCount = 2,
    DeltaFlowCount = 3,
    ProtocolIdentifier = 4,
    IPClassOfService = 5,
    TcpControlBits = 6,
    SourceTransportPort = 7,
    SourceIPv4Address = 8,
    SourceIPv4PrefixLength = 9,
    IngressInterface = 10,
    DestinationTransportPort = 11,
    DestinationIPv4Address = 12,
    DestinationIPv4PrefixLength = 13,
    EgressInterface = 14,
    IpNextHopIPv4Address = 15,
    BgpSourceAsNumber = 16,
    BgpDestinationAsNumber = 17,
    BgpNextHopIPv4Address = 18,
    PostMCastPacketDeltaCount = 19,
    PostMCastOctetDeltaCount = 20,
    FlowEndSysUpTime = 21,
    FlowStartSysUpTime = 22,
    PostOctetDeltaCount = 23,
    PostPacketDeltaCount = 24,
    MinimumIpTotalLength = 25,
    MaximumIpTotalLength = 26,
    SourceIPv6Address = 27,
    DestinationIPv6Address = 28,
    SourceIPv6PrefixLength = 29,
    DestinationIPv6PrefixLength = 30,
    FlowLabelIPv6 = 31,
    IcmpTypeCodeIPv4 = 32,
    IgmpType = 33,
    SamplingInterval = 34,
    SamplingAlgorithm = 35,
    FlowActiveTimeout = 36,
    FlowIdleTimeout = 37,
    EngineType = 38,
    EngineId = 39,
    ExportedOctetTotalCount = 40,
    ExportedMessageTotalCount = 41,
    ExportedFlowRecordTotalCount = 42,
    Ipv4RouterSc = 43,
    SourceIPv4Prefix = 44,
    DestinationIPv4Prefix = 45,
    MplsTopLabelType = 46,
    MplsTopLabelIPv4Address = 47,
    SamplerId = 48,
    SamplerMode = 49,
    SamplerRandomInterval = 50,
    ClassId = 51,
    MSinimumTTL = 52,
    MSaximumTTL = 53,
    FragmentIdentification = 54,
    PostIpClassOfService = 55,
    SourceMacAddress = 56,
    PostDestinationMacAddress = 57,
    VlanId = 58,
    PostVlanId = 59,
    IPVersion = 60,
    FlowDirection = 61,
    IpNextHopIPv6Address = 62,
    BgpNextHopIPv6Address = 63,
    Ipv6ExtensionHeaders = 64,
    // 65-69	Assigned for NetFlow v9 compatibility
    MplsTopLabelStackSection = 70,
    MplsLabelStackSection2 = 71,
    MplsLabelStackSection3 = 72,
    MplsLabelStackSection4 = 73,
    MplsLabelStackSection5 = 74,
    MplsLabelStackSection6 = 75,
    MplsLabelStackSection7 = 76,
    MplsLabelStackSection8 = 77,
    MplsLabelStackSection9 = 78,
    MplsLabelStackSection10 = 79,
    DestinationMacAddress = 80,
    PostSourceMacAddress = 81,
    InterfaceName = 82,
    InterfaceDescription = 83,
    SamplerName = 84,
    OctetTotalCount = 85,
    PacketTotalCount = 86,
    FlagsAndSamplerId = 87,
    FragmentOffset = 88,
    ForwardingStatus = 89,
    MplsVpnRouteDistinguisher = 90,
    MplsTopLabelPrefixLength = 91,
    SrcTrafficIndex = 92,
    DstTrafficIndex = 93,
    ApplicationDescription = 94,
    ApplicationId = 95,
    ApplicationName = 96,
    // 97	Assigned for NetFlow v9 compatibility
    PostIpDiffServCodePoint = 98,
    MSulticastReplicationFactor = 99,
    ClassName = 100,
    ClassificationEngineId = 101,
    Layer2packetSectionOffset = 102,
    Layer2packetSectionSize = 103,
    Layer2packetSectionData = 104,
    // 105-127	Assigned for NetFlow v9 compatibility
    BgpNextAdjacentAsNumber = 128,
    BgpPrevAdjacentAsNumber = 129,
    ExporterIPv4Address = 130,
    ExporterIPv6Address = 131,
    DroppedOctetDeltaCount = 132,
    DroppedPacketDeltaCount = 133,
    DroppedOctetTotalCount = 134,
    DroppedPacketTotalCount = 135,
    FlowEndReason = 136,
    CommonPropertiesId = 137,
    ObservationPointId = 138,
    IcmpTypeCodeIPv6 = 139,
    MplsTopLabelIPv6Address = 140,
    LineCardId = 141,
    PortId = 142,
    MeteringProcessId = 143,
    ExportingProcessId = 144,
    TemplateId = 145,
    WlanChannelId = 146,
    WlanSSID = 147,
    FlowId = 148,
    ObservationDomainId = 149,
    FlowStartSeconds = 150,
    FlowEndSeconds = 151,
    FlowStartMilliseconds = 152,
    FlowEndMilliseconds = 153,
    FlowStartMicroseconds = 154,
    FlowEndMicroseconds = 155,
    FlowStartNanoseconds = 156,
    FlowEndNanoseconds = 157,
    FlowStartDeltaMicroseconds = 158,
    FlowEndDeltaMicroseconds = 159,
    SystemInitTimeMilliseconds = 160,
    FlowDurationMilliseconds = 161,
    FlowDurationMicroseconds = 162,
    ObservedFlowTotalCount = 163,
    IgnoredPacketTotalCount = 164,
    IgnoredOctetTotalCount = 165,
    NotSentFlowTotalCount = 166,
    NotSentPacketTotalCount = 167,
    NotSentOctetTotalCount = 168,
    DestinationIPv6Prefix = 169,
    SourceIPv6Prefix = 170,
    PostOctetTotalCount = 171,
    PostPacketTotalCount = 172,
    FlowKeyIndicator = 173,
    PostMCastPacketTotalCount = 174,
    PostMCastOctetTotalCount = 175,
    IcmpTypeIPv4 = 176,
    IcmpCodeIPv4 = 177,
    IcmpTypeIPv6 = 178,
    IcmpCodeIPv6 = 179,
    UdpSourcePort = 180,
    UdpDestinationPort = 181,
    TcpSourcePort = 182,
    TcpDestinationPort = 183,
    TcpSequenceNumber = 184,
    TcpAcknowledgementNumber = 185,
    TcpWindowSize = 186,
    TcpUrgentPointer = 187,
    TcpHeaderLength = 188,
    IpHeaderLength = 189,
    TotalLengthIPv4 = 190,
    PayloadLengthIPv6 = 191,
    IpTTL = 192,
    NextHeaderIPv6 = 193,
    MplsPayloadLength = 194,
    IpDiffServCodePoint = 195,
    IpPrecedence = 196,
    FragmentFlags = 197,
    OctetDeltaSumOfSquares = 198,
    OctetTotalSumOfSquares = 199,
    MplsTopLabelTTL = 200,
    MplsLabelStackLength = 201,
    MplsLabelStackDepth = 202,
    MplsTopLabelExp = 203,
    IPPayloadLength = 204,
    UdpMessageLength = 205,
    IsMulticast = 206,
    IPv4IHL = 207,
    IPv4Options = 208,
    TcpOptions = 209,
    PaddingOctets = 210,
    CollectorIPv4Address = 211,
    CollectorIPv6Address = 212,
    ExportInterface = 213,
    ExportProtocolVersion = 214,
    ExportTransportProtocol = 215,
    CollectorTransportPort = 216,
    ExporterTransportPort = 217,
    TcpSynTotalCount = 218,
    TcpFinTotalCount = 219,
    TcpRstTotalCount = 220,
    TcpPshTotalCount = 221,
    TcpAckTotalCount = 222,
    TcpUrgTotalCount = 223,
    IpTotalLength = 224,
    PostNATSourceIPv4Address = 225,
    PostNATDestinationIPv4Address = 226,
    PostNAPTSourceTransportPort = 227,
    PostNAPTDestinationTransportPort = 228,
    NatOriginatingAddressRealm = 229,
    NatEvent = 230,
    InitiatorOctets = 231,
    ResponderOctets = 232,
    FirewallEvent = 233,
    IngressVRFID = 234,
    EgressVRFID = 235,
    VRFname = 236,
    PostMplsTopLabelExp = 237,
    TcpWindowScale = 238,
    BiflowDirection = 239,
    EthernetHeaderLength = 240,
    EthernetPayloadLength = 241,
    EthernetTotalLength = 242,
    Dot1qVlanId = 243,
    Dot1qPriority = 244,
    Dot1qCustomerVlanId = 245,
    Dot1qCustomerPriority = 246,
    MetroEvcId = 247,
    MetroEvcType = 248,
    PseudoWireId = 249,
    PseudoWireType = 250,
    PseudoWireControlWord = 251,
    IngressPhysicalInterface = 252,
    EgressPhysicalInterface = 253,
    PostDot1qVlanId = 254,
    PostDot1qCustomerVlanId = 255,
    EthernetType = 256,
    PostIpPrecedence = 257,
    CollectionTimeMilliseconds = 258,
    ExportSctpStreamId = 259,
    MaxExportSeconds = 260,
    MaxFlowEndSeconds = 261,
    MessageMD5Checksum = 262,
    MessageScope = 263,
    MinExportSeconds = 264,
    MinFlowStartSeconds = 265,
    OpaqueOctets = 266,
    SessionScope = 267,
    MaxFlowEndMicroseconds = 268,
    MaxFlowEndMilliseconds = 269,
    MaxFlowEndNanoseconds = 270,
    MinFlowStartMicroseconds = 271,
    MinFlowStartMilliseconds = 272,
    MinFlowStartNanoseconds = 273,
    CollectorCertificate = 274,
    ExporterCertificate = 275,
    DataRecordsReliability = 276,
    ObservationPointType = 277,
    NewConnectionDeltaCount = 278,
    ConnectionSumDurationSeconds = 279,
    ConnectionTransactionId = 280,
    PostNATSourceIPv6Address = 281,
    PostNATDestinationIPv6Address = 282,
    NatPoolId = 283,
    NatPoolName = 284,
    AnonymizationFlags = 285,
    AnonymizationTechnique = 286,
    InformationElementIndex = 287,
    P2PTechnology = 288,
    TunnelTechnology = 289,
    EncryptedTechnology = 290,
    BasicList = 291,
    SubTemplateList = 292,
    SubTemplateMultiList = 293,
    BgpValidityState = 294,
    IPSecSPI = 295,
    GreKey = 296,
    NatType = 297,
    InitiatorPackets = 298,
    ResponderPackets = 299,
    ObservationDomainName = 300,
    SelectionSequenceId = 301,
    SelectorId = 302,
    InformationElementId = 303,
    SelectorAlgorithm = 304,
    SamplingPacketInterval = 305,
    SamplingPacketSpace = 306,
    SamplingTimeInterval = 307,
    SamplingTimeSpace = 308,
    SamplingSize = 309,
    SamplingPopulation = 310,
    SamplingProbability = 311,
    DataLinkFrameSize = 312,
    IpHeaderPacketSection = 313,
    IpPayloadPacketSection = 314,
    DataLinkFrameSection = 315,
    MplsLabelStackSection = 316,
    MplsPayloadPacketSection = 317,
    SelectorIdTotalPktsObserved = 318,
    SelectorIdTotalPktsSelected = 319,
    AbsoluteError = 320,
    RelativeError = 321,
    ObservationTimeSeconds = 322,
    ObservationTimeMilliseconds = 323,
    ObservationTimeMicroseconds = 324,
    ObservationTimeNanoseconds = 325,
    DigestHashValue = 326,
    HashIPPayloadOffset = 327,
    HashIPPayloadSize = 328,
    HashOutputRangeMin = 329,
    HashOutputRangeMax = 330,
    HashSelectedRangeMin = 331,
    HashSelectedRangeMax = 332,
    HashDigestOutput = 333,
    HashInitialiserValue = 334,
    SelectorName = 335,
    UpperCILimit = 336,
    LowerCILimit = 337,
    ConfidenceLevel = 338,
    InformationElementDataType = 339,
    InformationElementDescription = 340,
    InformationElementName = 341,
    InformationElementRangeBegin = 342,
    InformationElementRangeEnd = 343,
    InformationElementSemantics = 344,
    InformationElementUnits = 345,
    PrivateEnterpriseNumber = 346,
    VirtualStationInterfaceId = 347,
    VirtualStationInterfaceName = 348,
    VirtualStationUUID = 349,
    VirtualStationName = 350,
    Layer2SegmentId = 351,
    Layer2OctetDeltaCount = 352,
    Layer2OctetTotalCount = 353,
    IngressUnicastPacketTotalCount = 354,
    IngressMulticastPacketTotalCount = 355,
    IngressBroadcastPacketTotalCount = 356,
    EgressUnicastPacketTotalCount = 357,
    EgressBroadcastPacketTotalCount = 358,
    MonitoringIntervalStartMilliSeconds = 359,
    MonitoringIntervalEndMilliSeconds = 360,
    PortRangeStart = 361,
    PortRangeEnd = 362,
    PortRangeStepSize = 363,
    PortRangeNumPorts = 364,
    StaMacAddress = 365,
    StaIPv4Address = 366,
    WtpMacAddress = 367,
    IngressInterfaceType = 368,
    EgressInterfaceType = 369,
    RtpSequenceNumber = 370,
    UserName = 371,
    ApplicationCategoryName = 372,
    ApplicationSubCategoryName = 373,
    ApplicationGroupName = 374,
    OriginalFlowsPresent = 375,
    OriginalFlowsInitiated = 376,
    OriginalFlowsCompleted = 377,
    DistinctCountOfSourceIPAddress = 378,
    DistinctCountOfDestinationIPAddress = 379,
    DistinctCountOfSourceIPv4Address = 380,
    DistinctCountOfDestinationIPv4Address = 381,
    DistinctCountOfSourceIPv6Address = 382,
    DistinctCountOfDestinationIPv6Address = 383,
    ValueDistributionMethod = 384,
    Rfc3550JitterMilliseconds = 385,
    Rfc3550JitterMicroseconds = 386,
    Rfc3550JitterNanoseconds = 387,
    Dot1qDEI = 388,
    Dot1qCustomerDEI = 389,
    FlowSelectorAlgorithm = 390,
    FlowSelectedOctetDeltaCount = 391,
    FlowSelectedPacketDeltaCount = 392,
    FlowSelectedFlowDeltaCount = 393,
    SelectorIDTotalFlowsObserved = 394,
    SelectorIDTotalFlowsSelected = 395,
    SamplingFlowInterval = 396,
    SamplingFlowSpacing = 397,
    FlowSamplingTimeInterval = 398,
    FlowSamplingTimeSpacing = 399,
    HashFlowDomain = 400,
    TransportOctetDeltaCount = 401,
    TransportPacketDeltaCount = 402,
    OriginalExporterIPv4Address = 403,
    OriginalExporterIPv6Address = 404,
    OriginalObservationDomainId = 405,
    IntermediateProcessId = 406,
    IgnoredDataRecordTotalCount = 407,
    DataLinkFrameType = 408,
    SectionOffset = 409,
    SectionExportedOctets = 410,
    Dot1qServiceInstanceTag = 411,
    Dot1qServiceInstanceId = 412,
    Dot1qServiceInstancePriority = 413,
    Dot1qCustomerSourceMacAddress = 414,
    Dot1qCustomerDestinationMacAddress = 415,
    PostLayer2OctetDeltaCount = 417,
    PostMCastLayer2OctetDeltaCount = 418,
    // 419 deprecated Duplicate of Information Element ID 353, layer2OctetTotalCount.
    PostLayer2OctetTotalCount = 420,
    PostMCastLayer2OctetTotalCount = 421,
    MinimumLayer2TotalLength = 422,
    MaximumLayer2TotalLength = 423,
    DroppedLayer2OctetDeltaCount = 424,
    DroppedLayer2OctetTotalCount = 425,
    IgnoredLayer2OctetTotalCount = 426,
    NotSentLayer2OctetTotalCount = 427,
    Layer2OctetDeltaSumOfSquares = 428,
    Layer2OctetTotalSumOfSquares = 429,
    Layer2FrameDeltaCount = 430,
    Layer2FrameTotalCount = 431,
    PseudoWireDestinationIPv4Address = 432,
    IgnoredLayer2FrameTotalCount = 433,
    MibObjectValueInteger = 434,
    MibObjectValueOctetString = 435,
    MibObjectValueOID = 436,
    MibObjectValueBits = 437,
    MibObjectValueIPAddress = 438,
    MibObjectValueCounter = 439,
    MibObjectValueGauge = 440,
    MibObjectValueTimeTicks = 441,
    MibObjectValueUnsigned = 442,
    MibObjectValueTable = 443,
    MibObjectValueRow = 444,
    MibObjectIdentifier = 445,
    MibSubIdentifier = 446,
    MibIndexIndicator = 447,
    MibCaptureTimeSemantics = 448,
    MibContextEngineID = 449,
    MibContextName = 450,
    MibObjectName = 451,
    MibObjectDescription = 452,
    MibObjectSyntax = 453,
    MibModuleName = 454,
    MobileIMSI = 455,
    MobileMSISDN = 456,
    HttpStatusCode = 457,
    SourceTransportPortsLimit = 458,
    HttpRequestMethod = 459,
    HttpRequestHost = 460,
    HttpRequestTarget = 461,
    HttpMessageVersion = 462,
    NatInstanceID = 463,
    InternalAddressRealm = 464,
    ExternalAddressRealm = 465,
    NatQuotaExceededEvent = 466,
    NatThresholdEvent = 467,
    HttpUserAgent = 468,
    HttpContentType = 469,
    HttpReasonPhrase = 470,
    MaxSessionEntries = 471,
    MaxBIBEntries = 472,
    MaxEntriesPerUser = 473,
    MaxSubscribers = 474,
    MaxFragmentsPendingReassembly = 475,
    AddressPoolHighThreshold = 476,
    AddressPoolLowThreshold = 477,
    AddressPortMappingHighThreshold = 478,
    AddressPortMappingLowThreshold = 479,
    AddressPortMappingPerUserHighThreshold = 480,
    GlobalAddressMappingHighThreshold = 481,
    VpnIdentifier = 482,
    BgpCommunity = 483,
    BgpSourceCommunityList = 484,
    BgpDestinationCommunityList = 485,
    BgpExtendedCommunity = 486,
    BgpSourceExtendedCommunityList = 487,
    BgpDestinationExtendedCommunityList = 488,
    BgpLargeCommunity = 489,
    BgpSourceLargeCommunityList = 490,
    BgpDestinationLargeCommunityList = 491,
    // 492-32767	Unassigned
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
