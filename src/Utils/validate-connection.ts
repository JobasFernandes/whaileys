import { Boom } from "@hapi/boom";
import { createHash } from "crypto";
import { proto } from "../../WAProto";
import {
  KEY_BUNDLE_TYPE,
  WA_ADV_ACCOUNT_SIG_PREFIX,
  WA_ADV_DEVICE_SIG_PREFIX,
  WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
} from "../Defaults";
import type { AuthenticationCreds, SignalCreds, SocketConfig } from "../Types";
import {
  BinaryNode,
  getBinaryNodeChild,
  jidDecode,
  S_WHATSAPP_NET
} from "../WABinary";
import { Curve, hmacSign } from "./crypto";
import { encodeBigEndian } from "./generics";
import { createSignalIdentity } from "./signal";

type ClientPayloadConfig = Pick<
  SocketConfig,
  "version" | "browser" | "syncFullHistory" | "countryCode"
>;

const getUserAgent = ({
  version
}: ClientPayloadConfig): proto.ClientPayload.IUserAgent => {
  const osVersion = "0.1";
  return {
    appVersion: {
      primary: version[0],
      secondary: version[1],
      tertiary: version[2]
    },
    platform: proto.ClientPayload.UserAgent.Platform.WEB,
    releaseChannel: proto.ClientPayload.UserAgent.ReleaseChannel.RELEASE,
    mcc: "000",
    mnc: "000",
    osVersion: osVersion,
    manufacturer: "",
    device: "Desktop",
    osBuildNumber: osVersion,
    localeLanguageIso6391: "en",
    localeCountryIso31661Alpha2: "US"
  };
};

const PLATFORM_MAP = {
  "Mac OS": proto.ClientPayload.WebInfo.WebSubPlatform.DARWIN,
  Windows: proto.ClientPayload.WebInfo.WebSubPlatform.WIN32
};

const getWebInfo = (
  config: ClientPayloadConfig
): proto.ClientPayload.IWebInfo => {
  let webSubPlatform = proto.ClientPayload.WebInfo.WebSubPlatform.WEB_BROWSER;
  if (config.syncFullHistory && PLATFORM_MAP[config.browser[0]]) {
    webSubPlatform = PLATFORM_MAP[config.browser[0]];
  }

  return { webSubPlatform };
};

const getClientPayload = (
  config: ClientPayloadConfig
): proto.IClientPayload => {
  return {
    connectType: proto.ClientPayload.ConnectType.WIFI_UNKNOWN,
    connectReason: proto.ClientPayload.ConnectReason.USER_ACTIVATED,
    userAgent: getUserAgent(config),
    webInfo: getWebInfo(config)
  };
};

export const generateLoginNode = (
  userJid: string,
  config: ClientPayloadConfig
): proto.IClientPayload => {
  const { user, device } = jidDecode(userJid)!;
  const payload: proto.IClientPayload = {
    ...getClientPayload(config),
    passive: true,
    pull: true,
    username: +user,
    device: device,
    lidDbMigrated: false
  };
  return proto.ClientPayload.fromObject(payload);
};

const getPlatformType = (platform: string): proto.DeviceProps.PlatformType => {
  const platformType = platform.toUpperCase();
  return (
    proto.DeviceProps.PlatformType[
      platformType as keyof typeof proto.DeviceProps.PlatformType
    ] || proto.DeviceProps.PlatformType.CHROME
  );
};

export const generateRegistrationNode = (
  { registrationId, signedPreKey, signedIdentityKey }: SignalCreds,
  config: ClientPayloadConfig
) => {
  // the app version needs to be md5 hashed
  // and passed in
  const appVersionBuf = createHash("md5")
    .update(config.version.join("."))
    .digest();
  const browserVersion = (config.browser[2] || "").split(".");

  const companion: proto.IDeviceProps = {
    os: config.browser[0],
    platformType: getPlatformType(config.browser[1]),
    requireFullSync: config.syncFullHistory,
    historySyncConfig: {
      storageQuotaMb: 10240,
      inlineInitialPayloadInE2EeMsg: true,
      recentSyncDaysLimit: undefined,
      supportCallLogHistory: false,
      supportBotUserAgentChatHistory: true,
      supportCagReactionsAndPolls: true,
      supportBizHostedMsg: true,
      supportRecentSyncChunkMessageCountTuning: true,
      supportHostedGroupMsg: true,
      supportFbidBotChatHistory: true,
      supportMessageAssociation: true,
      supportAddOnHistorySyncMigration: undefined,
      supportGroupHistory: false,
      onDemandReady: undefined,
      supportGuestChat: undefined
    },
    version: {
      primary: +(browserVersion[0] || 0),
      secondary: +(browserVersion[1] || 1),
      tertiary: +(browserVersion[2] || 0)
    }
  };

  const companionProto = proto.DeviceProps.encode(companion).finish();

  const registerPayload: proto.IClientPayload = {
    ...getClientPayload(config),
    passive: false,
    pull: false,
    devicePairingData: {
      buildHash: Uint8Array.from(appVersionBuf),
      deviceProps: companionProto,
      eRegid: encodeBigEndian(registrationId),
      eKeytype: Uint8Array.from(KEY_BUNDLE_TYPE),
      eIdent: signedIdentityKey.public,
      eSkeyId: encodeBigEndian(signedPreKey.keyId, 3),
      eSkeyVal: signedPreKey.keyPair.public,
      eSkeySig: signedPreKey.signature
    }
  };

  return proto.ClientPayload.fromObject(registerPayload);
};

export const configureSuccessfulPairing = (
  stanza: BinaryNode,
  {
    advSecretKey,
    signedIdentityKey,
    signalIdentities
  }: Pick<
    AuthenticationCreds,
    "advSecretKey" | "signedIdentityKey" | "signalIdentities"
  >
) => {
  const msgId = stanza.attrs.id;

  const pairSuccessNode = getBinaryNodeChild(stanza, "pair-success");

  const deviceIdentityNode = getBinaryNodeChild(
    pairSuccessNode,
    "device-identity"
  );
  const platformNode = getBinaryNodeChild(pairSuccessNode, "platform");
  const deviceNode = getBinaryNodeChild(pairSuccessNode, "device");
  const businessNode = getBinaryNodeChild(pairSuccessNode, "biz");

  if (!deviceIdentityNode || !deviceNode) {
    throw new Boom("Missing device-identity or device in pair success node", {
      data: stanza
    });
  }

  const bizName = businessNode?.attrs.name;
  const jid = deviceNode.attrs.jid;
  const lid = deviceNode.attrs.lid;

  const { details, hmac, accountType } =
    proto.ADVSignedDeviceIdentityHMAC.decode(
      deviceIdentityNode.content as Uint8Array
    );

  const hmacPrefix =
    accountType === proto.ADVEncryptionType.HOSTED
      ? WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
      : Buffer.from([]);

  // check HMAC matches
  const advPayload = new Uint8Array(hmacPrefix.length + details!.length);
  advPayload.set(hmacPrefix, 0);
  advPayload.set(details!, hmacPrefix.length);

  const advSign = hmacSign(advPayload, Buffer.from(advSecretKey, "base64"));
  if (!Buffer.from(hmac!).equals(new Uint8Array(advSign))) {
    throw new Boom("Invalid account signature");
  }

  const account = proto.ADVSignedDeviceIdentity.decode(details!);
  const {
    accountSignatureKey,
    accountSignature,
    details: deviceDetails
  } = account;

  const deviceIdentity = proto.ADVDeviceIdentity.decode(deviceDetails!);

  // verify the device signature matches
  const accountSignaturePrefix =
    deviceIdentity.deviceType === proto.ADVEncryptionType.HOSTED
      ? WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
      : WA_ADV_ACCOUNT_SIG_PREFIX;
  const accountMsgLength =
    accountSignaturePrefix.length +
    deviceDetails!.length +
    signedIdentityKey.public.length;
  const accountMsg = new Uint8Array(accountMsgLength);
  let accountOffset = 0;
  accountMsg.set(accountSignaturePrefix, accountOffset);
  accountOffset += accountSignaturePrefix.length;
  accountMsg.set(deviceDetails!, accountOffset);
  accountOffset += deviceDetails!.length;
  accountMsg.set(signedIdentityKey.public, accountOffset);

  if (!Curve.verify(accountSignatureKey!, accountMsg, accountSignature!)) {
    throw new Boom("Failed to verify account signature");
  }

  // sign the details with our identity key
  const deviceMsgLength =
    WA_ADV_DEVICE_SIG_PREFIX.length +
    deviceDetails!.length +
    signedIdentityKey.public.length +
    accountSignatureKey!.length;
  const deviceMsg = new Uint8Array(deviceMsgLength);
  let deviceOffset = 0;
  deviceMsg.set(WA_ADV_DEVICE_SIG_PREFIX, deviceOffset);
  deviceOffset += WA_ADV_DEVICE_SIG_PREFIX.length;
  deviceMsg.set(deviceDetails!, deviceOffset);
  deviceOffset += deviceDetails!.length;
  deviceMsg.set(signedIdentityKey.public, deviceOffset);
  deviceOffset += signedIdentityKey.public.length;
  deviceMsg.set(accountSignatureKey!, deviceOffset);

  account.deviceSignature = Curve.sign(signedIdentityKey.private, deviceMsg);

  const identity = createSignalIdentity(lid!, accountSignatureKey!);
  const accountEnc = encodeSignedDeviceIdentity(account, false);

  const reply: BinaryNode = {
    tag: "iq",
    attrs: {
      to: S_WHATSAPP_NET,
      type: "result",
      id: msgId!
    },
    content: [
      {
        tag: "pair-device-sign",
        attrs: {},
        content: [
          {
            tag: "device-identity",
            attrs: { "key-index": deviceIdentity.keyIndex!.toString() },
            content: accountEnc
          }
        ]
      }
    ]
  };

  const authUpdate: Partial<AuthenticationCreds> = {
    account,
    me: { id: jid!, name: bizName, lid },
    signalIdentities: [...(signalIdentities || []), identity],
    platform: platformNode?.attrs.name
  };

  return {
    creds: authUpdate,
    reply
  };
};

export const encodeSignedDeviceIdentity = (
  account: proto.IADVSignedDeviceIdentity,
  includeSignatureKey: boolean
) => {
  account = { ...account };
  // set to null if we are not to include the signature key
  // or if we are including the signature key but it is empty
  if (!includeSignatureKey || !account.accountSignatureKey?.length) {
    account.accountSignatureKey = null;
  }

  const accountEnc = proto.ADVSignedDeviceIdentity.encode(account).finish();
  return accountEnc;
};
