use core::convert::TryInto;
use num_traits::FromPrimitive;
use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::flow::Flow;

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

#[derive(Debug, PartialEq)]
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

/******************************** DATA SET ********************************/

#[derive(Debug)]
pub struct DataSet {
    pub fields: HashMap<FieldType, FieldValue>,
}

impl DataSet {
    pub const MIN_SET_ID: u16 = 256;

    pub fn read(buf: &[u8], field_list: &Vec<TemplateField>, min_size: usize) -> Result<Self, String> {
        if buf.len() < min_size {
            return Err(format!("Not enough space in buffer to read IPFIX DataSet, required {} but received {}", min_size, buf.len()));
        }

        let mut fields = HashMap::with_capacity(field_list.len());
        let mut offset = 0;

        for field in field_list {
            fields.insert(
                field.id,
                match field.length {
                    1 => FieldValue::U8(buf[offset]),
                    2 => FieldValue::U16(u16::from_be_bytes(buf[offset..offset + 2].try_into().unwrap())),
                    4 => FieldValue::U32(u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap())),
                    8 => FieldValue::U64(u64::from_be_bytes(buf[offset..offset + 8].try_into().unwrap())),
                    16 => FieldValue::U128(u128::from_be_bytes(buf[offset..offset + 16].try_into().unwrap())),
                    _ => FieldValue::Dyn(buf[offset..offset + field.length as usize].to_vec()),
                },
            );
            offset += field.length as usize;
        }

        Ok(DataSet { fields })
    }

    pub fn add_sampling(&mut self, sampling: u64) {
        if sampling > 0 {
            if let Some(FieldValue::U64(v)) = self.fields.get_mut(&FieldType::OctetDeltaCount) {
                *v *= sampling
            }

            if let Some(FieldValue::U64(v)) = self.fields.get_mut(&FieldType::PacketDeltaCount) {
                *v *= sampling
            }
        }
    }
}

impl Flow for DataSet {}

impl fmt::Display for DataSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (ftype, fvalue) in self.fields.iter() {
            match (ftype, fvalue) {
                (FieldType::SourceIPv4Address, FieldValue::U32(v)) | (FieldType::DestinationIPv4Address, FieldValue::U32(v)) | (FieldType::ExporterIPv4Address, FieldValue::U32(v)) => {
                    write!(f, "{:?}: {}, ", ftype, Ipv4Addr::from(*v))?
                }
                (FieldType::SourceIPv6Address, FieldValue::U128(v)) | (FieldType::DestinationIPv6Prefix, FieldValue::U128(v)) | (FieldType::ExporterIPv6Address, FieldValue::U128(v)) => {
                    write!(f, "{:?}: {}, ", ftype, Ipv6Addr::from(*v))?
                }
                _ => write!(f, "{:?}: {}, ", ftype, fvalue)?,
            }
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

/******************************** DATA SET TEMPLATE ********************************/

pub struct DataSetTemplate {
    pub header: TemplateHeader,
    pub fields: Vec<TemplateField>,
    pub length: usize,
}

impl DataSetTemplate {
    pub const SET_ID: u16 = 2;

    pub fn read(buf: &[u8]) -> Result<(Self, usize), String> {
        let header = TemplateHeader::read(&buf)?;
        let mut fields: Vec<TemplateField> = vec![];
        let mut offset = TemplateHeader::SIZE;
        let mut length = 0;

        for _ in 0..header.field_count {
            let field = TemplateField::read(&buf[offset..])?;
            length += field.length as usize;
            fields.push(field);
            offset += TemplateField::SIZE;
        }

        Ok((DataSetTemplate { header, fields, length }, offset))
    }
}

impl fmt::Display for DataSetTemplate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", &self.header)?;
        write!(f, "length: {} ", &self.length)?;

        for field in &self.fields {
            write!(f, "\n{:?}", field)?;
        }

        Ok(())
    }
}

/******************************** OPTION DATA SET TEMPLATE ********************************/

pub struct OptionDataSetTemplate {
    pub header: OptionTemplateHeader,
    pub fields: Vec<TemplateField>,
    pub length: usize,
}

impl OptionDataSetTemplate {
    pub const SET_ID: u16 = 3;

    pub fn read(buf: &[u8]) -> Result<(Self, usize), String> {
        let header = OptionTemplateHeader::read(&buf)?;
        let mut fields: Vec<TemplateField> = vec![];
        let mut offset = OptionTemplateHeader::SIZE;
        let mut length = 0;

        for _ in 0..header.field_count {
            let field = TemplateField::read(&buf[offset..])?;
            length += field.length as usize;
            fields.push(field);
            offset += TemplateField::SIZE;
        }

        Ok((OptionDataSetTemplate { header, fields, length }, offset))
    }
}

impl fmt::Display for OptionDataSetTemplate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", &self.header)?;
        write!(f, "length: {}", &self.length)?;

        for field in &self.fields {
            write!(f, "\n{:?}", field)?;
        }

        Ok(())
    }
}

/******************************** IPFIX FIELD TYPE ********************************/

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
#[derive(Debug, PartialEq)]
pub enum FieldValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    Dyn(Vec<u8>),
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FieldValue::U8(v) => v.fmt(f),
            FieldValue::U16(v) => v.fmt(f),
            FieldValue::U32(v) => v.fmt(f),
            FieldValue::U64(v) => v.fmt(f),
            FieldValue::U128(v) => v.fmt(f),
            FieldValue::Dyn(v) => write!(f, "{:?}", v), // to improve
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

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const HEADER_PAYLOD: [u8; Header::SIZE] = hex!("00 0a 00 84 60 6c 55 89 df b2 ba d2 00 08 00 00");

    const SET_HEADER_PAYLOAD: [u8; SetHeader::SIZE] = hex!("00 02 00 74");

    const TEMPLATE_PAYLOAD: [u8; 112] = hex!(
        "01 00 00 1b 00 08 00 04 00 0c 00 04 00 05 00 01
         00 04 00 01 00 07 00 02 00 0b 00 02 00 20 00 02
         00 0a 00 04 00 3a 00 02 00 09 00 01 00 0d 00 01
         00 10 00 04 00 11 00 04 00 0f 00 04 00 06 00 01
         00 0e 00 04 00 01 00 08 00 02 00 08 00 34 00 01
         00 35 00 01 00 98 00 08 00 99 00 08 00 88 00 01
         00 3d 00 01 00 f3 00 02 00 f5 00 02 00 36 00 04"
    );

    const OPTION_TEMPLATE_PAYLOAD: [u8; 50] = hex!(
        "02 00 00 0b 00 01 00 90 00 04 00 29 00 08 00 2a 
         00 08 00 a0 00 08 00 82 00 04 00 83 00 10 00 22 
         00 04 00 24 00 02 00 25 00 02 00 d6 00 01 00 d7 
         00 01"
    );

    const DATASET: [u8; 85] = hex!(
        "c3 05 ed 5a 34 71 91 de 00 11 f0 58 0d 98 00 00
         00 00 02 2d 00 00 1e 0e 00 00 33 89 00 00 1f 8b
         c3 42 e0 8c 00 00 00 02 2c 00 00 00 00 00 00 12
         6a 00 00 00 00 00 00 00 25 75 75 00 00 01 78 a7
         2c c9 00 00 00 01 78 a7 2e 2a 00 02 ff 00 00 00
         00 00 00 00 00"
    );

    const OPTION_DATASET: [u8; 58] = hex!(
        "00 00 00 02 00 00 00 09 31 c3 26 c6 00 00 00 26
         5b 7e cc 9b 00 00 01 4a a2 d7 85 28 b2 84 10 20
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 0a 00 0a 00 0a 0a 11"
    );

    #[test]
    fn read_msg_header() {
        let header = Header::read(&HEADER_PAYLOD).unwrap();

        assert_eq!(header.version, VERSION);
        assert_eq!(header.length, 132);
        assert_eq!(header.export_time, 1617712521);
        assert_eq!(header.seq_number, 3753032402);
        assert_eq!(header.domain_id, 524288);
    }

    #[test]
    #[should_panic]
    fn read_invalid_msg_header() {
        Header::read(&HEADER_PAYLOD[0..HEADER_PAYLOD.len() - 1]).unwrap();
    }

    #[test]
    fn read_set_header() {
        let set = SetHeader::read(&SET_HEADER_PAYLOAD).unwrap();

        assert_eq!(set.id, 2);
        assert_eq!(set.length, 116);
    }

    #[test]
    #[should_panic]
    fn read_invalid_set_header() {
        SetHeader::read(&SET_HEADER_PAYLOAD[0..SET_HEADER_PAYLOAD.len() - 1]).unwrap();
    }

    #[test]
    fn read_data_template() {
        let (template, size_read) = DataSetTemplate::read(&TEMPLATE_PAYLOAD).unwrap();

        assert_eq!(template.header.id, 256);
        assert_eq!(template.header.field_count, 27);
        assert_eq!(size_read, TEMPLATE_PAYLOAD.len());
        assert_eq!(template.fields.len(), template.header.field_count as usize);

        #[cfg_attr(rustfmt, rustfmt::skip)]
        {
        assert_eq!(template.fields[0], TemplateField {id: FieldType::SourceIPv4Address, length: 4});
        assert_eq!(template.fields[1], TemplateField {id: FieldType::DestinationIPv4Address, length: 4});
        assert_eq!(template.fields[2], TemplateField {id: FieldType::IPClassOfService, length: 1});
        assert_eq!(template.fields[3], TemplateField {id: FieldType::ProtocolIdentifier, length: 1});
        assert_eq!(template.fields[4], TemplateField {id: FieldType::SourceTransportPort, length: 2});
        assert_eq!(template.fields[5], TemplateField {id: FieldType::DestinationTransportPort, length: 2});
        assert_eq!(template.fields[6], TemplateField {id: FieldType::IcmpTypeCodeIPv4, length: 2});
        assert_eq!(template.fields[7], TemplateField {id: FieldType::IngressInterface, length: 4});
        assert_eq!(template.fields[8], TemplateField {id: FieldType::VlanId, length: 2});
        assert_eq!(template.fields[9], TemplateField {id: FieldType::SourceIPv4PrefixLength, length: 1});
        assert_eq!(template.fields[10], TemplateField {id: FieldType::DestinationIPv4PrefixLength, length: 1});
        assert_eq!(template.fields[11], TemplateField {id: FieldType::BgpSourceAsNumber, length: 4});
        assert_eq!(template.fields[12], TemplateField {id: FieldType::BgpDestinationAsNumber, length: 4});
        assert_eq!(template.fields[13], TemplateField {id: FieldType::IpNextHopIPv4Address, length: 4});
        assert_eq!(template.fields[14], TemplateField {id: FieldType::TcpControlBits, length: 1});
        assert_eq!(template.fields[15], TemplateField {id: FieldType::EgressInterface, length: 4});
        assert_eq!(template.fields[16], TemplateField {id: FieldType::OctetDeltaCount, length: 8});
        assert_eq!(template.fields[17], TemplateField {id: FieldType::PacketDeltaCount, length: 8});
        assert_eq!(template.fields[18], TemplateField {id: FieldType::MSinimumTTL, length: 1});
        assert_eq!(template.fields[19], TemplateField {id: FieldType::MSaximumTTL, length: 1});
        assert_eq!(template.fields[20], TemplateField {id: FieldType::FlowStartMilliseconds, length: 8});
        assert_eq!(template.fields[21], TemplateField {id: FieldType::FlowEndMilliseconds, length: 8});
        assert_eq!(template.fields[22], TemplateField {id: FieldType::FlowEndReason, length: 1});
        assert_eq!(template.fields[23], TemplateField {id: FieldType::FlowDirection, length: 1});
        assert_eq!(template.fields[24], TemplateField {id: FieldType::Dot1qVlanId, length: 2});
        assert_eq!(template.fields[25], TemplateField {id: FieldType::Dot1qCustomerVlanId, length: 2});
        assert_eq!(template.fields[26], TemplateField {id: FieldType::FragmentIdentification, length: 4});
        }
    }

    #[test]
    #[should_panic]
    fn read_invalid_data_template() {
        DataSetTemplate::read(&TEMPLATE_PAYLOAD[0..TEMPLATE_PAYLOAD.len() - 1]).unwrap();
    }

    #[test]
    fn read_option_template() {
        let (template, size_read) = OptionDataSetTemplate::read(&OPTION_TEMPLATE_PAYLOAD).unwrap();

        assert_eq!(template.header.id, 512);
        assert_eq!(template.header.field_count, 11);
        assert_eq!(template.header.scope_field_count, 1);
        assert_eq!(template.length, 58);
        assert_eq!(size_read, OPTION_TEMPLATE_PAYLOAD.len());
        assert_eq!(template.fields.len(), template.header.field_count as usize);

        #[cfg_attr(rustfmt, rustfmt::skip)]
        {
        assert_eq!(template.fields[0], TemplateField {id: FieldType::ExportingProcessId, length: 4});
        assert_eq!(template.fields[1], TemplateField {id: FieldType::ExportedMessageTotalCount, length: 8});
        assert_eq!(template.fields[2], TemplateField {id: FieldType::ExportedFlowRecordTotalCount, length: 8});
        assert_eq!(template.fields[3], TemplateField {id: FieldType::SystemInitTimeMilliseconds, length: 8});
        assert_eq!(template.fields[4], TemplateField {id: FieldType::ExporterIPv4Address, length: 4});
        assert_eq!(template.fields[5], TemplateField {id: FieldType::ExporterIPv6Address, length: 16});
        assert_eq!(template.fields[6], TemplateField {id: FieldType::SamplingInterval, length: 4});
        assert_eq!(template.fields[7], TemplateField {id: FieldType::FlowActiveTimeout, length: 2});
        assert_eq!(template.fields[8], TemplateField {id: FieldType::FlowIdleTimeout, length: 2});
        assert_eq!(template.fields[9], TemplateField {id: FieldType::ExportProtocolVersion, length: 1});
        assert_eq!(template.fields[10], TemplateField {id: FieldType::ExportTransportProtocol, length: 1});   
        }
    }

    #[test]
    #[should_panic]
    fn read_invalid_option_template() {
        OptionDataSetTemplate::read(&OPTION_TEMPLATE_PAYLOAD[0..OPTION_TEMPLATE_PAYLOAD.len() - 1]).unwrap();
    }

    #[test]
    fn readd_dataset() {
        let (template, _) = DataSetTemplate::read(&TEMPLATE_PAYLOAD).unwrap();
        let msg = DataSet::read(&DATASET, &template.fields, template.length).unwrap();

        assert_eq!(msg.fields.len(), template.fields.len());
        assert_eq!(msg.fields.get(&FieldType::SourceIPv4Address), Some(&FieldValue::U32(u32::from(Ipv4Addr::new(195, 5, 237, 90)))));
        assert_eq!(msg.fields.get(&FieldType::DestinationIPv4Address), Some(&FieldValue::U32(u32::from(Ipv4Addr::new(52, 113, 145, 222)))));
        assert_eq!(msg.fields.get(&FieldType::IPClassOfService), Some(&FieldValue::U8(0)));
        assert_eq!(msg.fields.get(&FieldType::ProtocolIdentifier), Some(&FieldValue::U8(17)));
        assert_eq!(msg.fields.get(&FieldType::SourceTransportPort), Some(&FieldValue::U16(61528)));
        assert_eq!(msg.fields.get(&FieldType::DestinationTransportPort), Some(&FieldValue::U16(3480)));
        assert_eq!(msg.fields.get(&FieldType::IcmpTypeCodeIPv4), Some(&FieldValue::U16(0)));
        assert_eq!(msg.fields.get(&FieldType::IngressInterface), Some(&FieldValue::U32(557)));
        assert_eq!(msg.fields.get(&FieldType::VlanId), Some(&FieldValue::U16(0)));
        assert_eq!(msg.fields.get(&FieldType::SourceIPv4PrefixLength), Some(&FieldValue::U8(30)));
        assert_eq!(msg.fields.get(&FieldType::DestinationIPv4PrefixLength), Some(&FieldValue::U8(14)));
        assert_eq!(msg.fields.get(&FieldType::BgpSourceAsNumber), Some(&FieldValue::U32(13193)));
        assert_eq!(msg.fields.get(&FieldType::BgpDestinationAsNumber), Some(&FieldValue::U32(8075)));
        assert_eq!(msg.fields.get(&FieldType::IpNextHopIPv4Address), Some(&FieldValue::U32(u32::from(Ipv4Addr::new(195, 66, 224, 140)))));
        assert_eq!(msg.fields.get(&FieldType::TcpControlBits), Some(&FieldValue::U8(0)));
        assert_eq!(msg.fields.get(&FieldType::EgressInterface), Some(&FieldValue::U32(556)));
        assert_eq!(msg.fields.get(&FieldType::OctetDeltaCount), Some(&FieldValue::U64(4714)));
        assert_eq!(msg.fields.get(&FieldType::PacketDeltaCount), Some(&FieldValue::U64(37)));
        assert_eq!(msg.fields.get(&FieldType::MSinimumTTL), Some(&FieldValue::U8(117)));
        assert_eq!(msg.fields.get(&FieldType::MSaximumTTL), Some(&FieldValue::U8(117)));
        assert_eq!(msg.fields.get(&FieldType::FlowStartMilliseconds), Some(&FieldValue::U64(1617712433408)));
        assert_eq!(msg.fields.get(&FieldType::FlowEndMilliseconds), Some(&FieldValue::U64(1617712523776)));
        assert_eq!(msg.fields.get(&FieldType::FlowEndReason), Some(&FieldValue::U8(2)));
        assert_eq!(msg.fields.get(&FieldType::FlowDirection), Some(&FieldValue::U8(255)));
        assert_eq!(msg.fields.get(&FieldType::Dot1qVlanId), Some(&FieldValue::U16(0)));
        assert_eq!(msg.fields.get(&FieldType::Dot1qCustomerVlanId), Some(&FieldValue::U16(0)));
        assert_eq!(msg.fields.get(&FieldType::FragmentIdentification), Some(&FieldValue::U32(0)));
    }

    #[test]
    #[should_panic]
    fn read_invalid_dataset() {
        let (template, _) = DataSetTemplate::read(&TEMPLATE_PAYLOAD).unwrap();
        DataSet::read(&DATASET[0..DATASET.len() - 1], &template.fields, template.length).unwrap();
    }

    #[test]
    fn read_option_dataset() {
        let (template, _) = OptionDataSetTemplate::read(&OPTION_TEMPLATE_PAYLOAD).unwrap();
        let msg = DataSet::read(&OPTION_DATASET, &template.fields, template.length).unwrap();

        assert_eq!(msg.fields.len(), template.fields.len());

        assert_eq!(msg.fields.get(&FieldType::ExportingProcessId), Some(&FieldValue::U32(2)));
        assert_eq!(msg.fields.get(&FieldType::ExportedMessageTotalCount), Some(&FieldValue::U64(39489578694)));
        assert_eq!(msg.fields.get(&FieldType::SamplingInterval), Some(&FieldValue::U32(10)));
        assert_eq!(msg.fields.get(&FieldType::ExportProtocolVersion), Some(&FieldValue::U8(VERSION as u8)));
        assert_eq!(msg.fields.get(&FieldType::SystemInitTimeMilliseconds), Some(&FieldValue::U64(1420071241000)));
        assert_eq!(msg.fields.get(&FieldType::ExporterIPv6Address), Some(&FieldValue::U128(u128::from("::".parse::<Ipv6Addr>().unwrap()))));
        assert_eq!(msg.fields.get(&FieldType::FlowIdleTimeout), Some(&FieldValue::U16(10)));
        assert_eq!(msg.fields.get(&FieldType::ExporterIPv4Address), Some(&FieldValue::U32(u32::from(Ipv4Addr::new(178, 132, 16, 32)))));
        assert_eq!(msg.fields.get(&FieldType::ExportTransportProtocol), Some(&FieldValue::U8(17)));
        assert_eq!(msg.fields.get(&FieldType::FlowActiveTimeout), Some(&FieldValue::U16(10)));
        assert_eq!(msg.fields.get(&FieldType::ExportedFlowRecordTotalCount), Some(&FieldValue::U64(164743793819)));
    }

    #[test]
    #[should_panic]
    fn read_invalid_option_dataset() {
        let (template, _) = OptionDataSetTemplate::read(&TEMPLATE_PAYLOAD).unwrap();
        DataSet::read(&OPTION_DATASET[0..OPTION_DATASET.len() - 1], &template.fields, template.length).unwrap();
    }
}
