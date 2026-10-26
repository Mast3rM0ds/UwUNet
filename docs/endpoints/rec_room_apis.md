# Rec Room API Endpoints (Schools Out Update)
> Compiled from community findings — Discussion #8 by AdvertRR

## Social & Relationships
| Endpoint                                            | Method | Notes                                |
| --------------------------------------------------- | ------ | ------------------------------------ |
| `/api/relationships/v2/get`                         | GET    | Get relationships                    |
| `/api/relationships/v1/ignore`                      | POST   | Ignore a player                      |
| `/api/relationships/v1/unignore`                    | POST   | Unignore a player                    |
| `/api/relationships/v1/mute`                        | POST   | Mute a player                        |
| `/api/relationships/v1/unmute`                      | POST   | Unmute a player                      |
| `/api/messages/v1/friendOnlineStatus`               | GET    | Check if friends are online          |
| `/api/messages/v2/get`                              | GET    | Get messages                         |
| `/api/externalfriendinvite/v1/getplatformreferrers` | GET    | Get platform friend invite referrers |
| `/chat/thread`                                      | GET    | Chat threads                         |
| `/chat/thread/party`                                | GET    | Party chat thread                    |
| `/chat/thread/chatPrivacySetting`                   | GET    | Chat privacy settings                |


## Players & Profiles
| Endpoint                                    | Method | Notes                         |
| ------------------------------------------- | ------ | ----------------------------- |
| `/api/players/v1/playerPhotoTaggingSetting` | GET    | Photo tagging setting         |
| `/api/players/v2/progression/bulk?id=`      | GET    | Bulk player progression by ID |
| `/api/progressionEvents/active`             | GET    | Active progression events     |
| `/api/progressionEvents/event/id`           | GET    | Progression event             |
| `/api/purchasableXpBoosts/activations`      | GET    | XP boost activations          |
| `/api/playerReputation/v2/bulk?id=`         | GET    | Bulk player reputation by ID  |

## Accounts & Session
| Endpoint                                    | Method | Notes                          |
| ------------------------------------------- | ------ | ------------------------------ |
| `/Accounts/account/me`                      | GET    | Current account information    |
| `/Accounts/account/bulk`                    | GET    | Bulk account lookup            |
| `/Accounts/parentalcontrol/me`              | GET    | Parental control settings      |
| `/Matchmaking/player`                       | GET    | Current player state           |
| `/Matchmaking/player/login`                 | POST   | Player login                   |
| `/Matchmaking/player/logout`                | POST   | Player logout                  |
| `/Matchmaking/player/heartbeat`             | POST   | Session heartbeat              |
| `/Matchmaking/player/qos`                   | GET    | Quality-of-service information |
| `/Matchmaking/player/connection-info`       | GET    | Connection information         |
| `/Matchmaking/player/exclusivelogin`        | POST   | Exclusive login handling       |
| `/Matchmaking/player/gameserverregionpings` | PUT    | Region ping submission         |
| `/Matchmaking/player/statusvisibility`      | PUT    | Online visibility setting      |

## Matchmaking
| Endpoint                                          | Method | Notes                   |
| ------------------------------------------------- | ------ | ----------------------- |
| `/Matchmaking/matchmake/dorm`                     | POST   | Join dorm room          |
| `/Matchmaking/matchmake/v2/room/{id}`             | POST   | Matchmake into room     |
| `/Matchmaking/matchmake/none`                     | POST   | Leave matchmaking       |
| `/Matchmaking/roominstance/{id}/reportjoinresult` | POST   | Report room join result |
| `/Matchmaking/rooms/requiring/developer`          | GET    | Developer-gated rooms   |
| `/Matchmaking/rooms/requiring/rrplus`             | GET    | RR+ gated rooms         |


## Rooms
| Endpoint                                              | Method | Notes                       |
| ----------------------------------------------------- | ------ | --------------------------- |
| `/api/rooms/v1/filters`                               | GET    | Room filter options         |
| `/api/rooms/v1/verifyRole`                            | POST   | Verify player role in room  |
| `/api/rooms/v3/report`                                | POST   | Report a room               |
| `/api/quickPlay/v1/getandclear`                       | POST   | Quick play queue            |
| `/Room_server/rooms`                                  | GET    | Room listing                |
| `/Room_server/rooms/{id}`                             | GET    | Room details                |
| `/Room_server/rooms/bulk`                             | GET    | Bulk room lookup            |
| `/Room_server/dormroom/me`                            | GET    | User dorm room              |
| `/Room_server/featuredrooms/current`                  | GET    | Featured rooms              |
| `/Room_server/rooms/hot`                              | GET    | Hot rooms                   |
| `/Room_server/rooms/search`                           | GET    | Room search                 |
| `/Room_server/rooms/autocomplete_search`              | GET    | Room search suggestions     |
| `/Room_server/rooms/ownedby/me`                       | GET    | Rooms owned by current user |
| `/Room_server/rooms/visitedby/me`                     | GET    | Recently visited rooms      |
| `/Room_server/rooms/{id}/experience`                  | GET    | Room experience metadata    |
| `/Room_server/rooms/{id}/experience/player`           | GET    | Player room experience      |
| `/Room_server/rooms/{id}/interactionby/me`            | GET    | Player interaction state    |
| `/Room_server/rooms/{id}/subrooms/{sub}/saves/{save}` | GET    | Subroom save data           |
| `/Room_server/photon_access_token`                    | GET    | Photon networking token     |
| `/Room_server/publishState/configs`                   | GET    | Publish state configuration |

## Images & Media
| Endpoint | Method | Notes |
|----------|--------|-------|
| `/api/images/v2/named` | GET | Named images |
| `/api/images/v5/cheered/bulk` | GET | Bulk cheered images |
| `/api/images/v1/cheer` | POST | Cheer an image |
| `/api/PlayerCheer/v1/create` | POST | Create a player cheer |

## Moderation & Reporting
| Endpoint                                         | Method | Notes                     |
| ------------------------------------------------ | ------ | ------------------------- |
| `/api/PlayerReporting/v1/voteToKickReasons`      | GET    | Vote-to-kick reason list  |
| `/api/PlayerReporting/v1/moderationBlockDetails` | GET    | Moderation block details  |
| `/api/PlayerReporting/v1/roomModKick`            | POST   | Room mod kick action      |
| `/api/sanitize/v1`                               | POST   | Sanitize content          |
| `/api/sanitize/v1/isPure`                        | GET    | Check if content is clean |

## Avatar & Outfits
| Endpoint                                                | Method | Notes                             |
| ------------------------------------------------------- | ------ | --------------------------------- |
| `/api/customAvatarItems/v1/bulk`                        | GET    | Bulk custom avatar items          |
| `/api/customAvatarItems/v1/isRenderingEnabled`          | GET    | Check if rendering is enabled     |
| `/api/customAvatarItems/v1/isCreationEnabled`           | GET    | Check if creation is enabled      |
| `/api/customAvatarItems/v1/isCreationAllowedForAccount` | GET    | Account-level creation permission |
| `/outfits/me/saved`                                     | GET    | Saved outfits                     |

## Inventions
| Endpoint | Method | Notes |
|----------|--------|-------|
| `/api/inventions/v2/mine` | GET | My inventions |
| `/api/inventions/v1/room?id=` | GET | Room inventions by ID |

## Clubs
| Endpoint                                           | Method | Notes                             |
| -------------------------------------------------- | ------ | --------------------------------- |
| `/clubs/announcements/v2/mine/unread`              | GET    | Unread club announcements         |
| `/clubs/announcements/v2/subscription/mine/unread` | GET    | Unread subscription announcements |
| `/clubs/club/home/me`                              | GET    | Club home information             |
| `/clubs/club/mine/member`                          | GET    | Club memberships                  |
| `/clubs/subscription/mine/member`                  | GET    | Subscription memberships          |

## Messaging & Notifications
| Endpoint                          | Method | Notes                        |
| --------------------------------- | ------ | ---------------------------- |
| `/Notifications/hub/v1`           | GET    | Notification hub             |
| `/Notifications/hub/v1/negotiate` | POST   | Notification hub negotiation |
| `/Notifications/crm/me/config/v3` | GET    | Notification configuration   |

## Economy & Commerce
| Endpoint                                   | Method | Notes                     |
| ------------------------------------------ | ------ | ------------------------- |
| `/econ/roomInventory/room/{id}`            | GET    | Room inventory            |
| `/econ/roomInventory/room/{id}/player`     | GET    | Player room inventory     |
| `/econ/roomInventoryItemTags/room/{id}`    | GET    | Inventory item tags       |
| `/econ/roomOffer/room/{id}`                | GET    | Room offers               |
| `/econ/roomOffer/room/{id}/purchaseCounts` | GET    | Offer purchase counts     |
| `/econ/roomGiftDropShops/room/{id}`        | GET    | Gift drop shops           |
| `/econ/roomEconConfig/{id}`                | GET    | Economy configuration     |
| `/Commerce/api/catalog/v1/all`             | GET    | Commerce catalog          |
| `/Commerce/purchasecampaign/allcurrent/v2` | GET    | Active purchase campaigns |
| `/api/storefronts/v4/balance/{currency}`   | GET    | Currency balance          |
| `/api/storefronts/v3/giftdropstore/{id}`   | GET    | Gift drop storefront      |

## Config & Misc
| Endpoint                             | Method | Notes                    |
| ------------------------------------ | ------ | ------------------------ |
| `/api/config/v2`                     | GET    | App config               |
| `/api/gameconfigs/v1/all`            | GET    | Game configs             |
| `/api/versioncheck/islandedversions` | GET    | Islanded version check   |
| `/api/keepsakes/globalconfig`        | GET    | Keepsakes global config  |
| `/api/keepsakes/categories`          | GET    | Keepsakes categories     |
| `/api/playerevents/v1/all`           | GET    | All player events        |
| `/api/playerevents/v1/tagfilters`    | GET    | Player event tag filters |
| `/api/communityboard/v2/current`     | GET    | Current community board  |
| `/statsigUserProperties`             | GET    | Statsig user properties  |

## Authentication
| Endpoint                           | Method | Notes                       |
| ---------------------------------- | ------ | --------------------------- |
| `/Auth/connect/token`              | POST   | OAuth token login           |
| `/Auth/cachedlogin/forplatformids` | POST   | Cached platform login       |
| `/Auth/role/developer`             | GET    | Developer role verification |

## Content Moderation
| Endpoint | Method | Notes |
|----------|--------|-------|
| `/api/sanitize/v1` | POST | Sanitize content |
| `/api/sanitize/v1/isPure` | GET | Check if content is clean |

---

**Base URL:** `https://api.rec.net`

**Source:** Community-gathered via HTTP debugging (AdvertRR, RestoRoom Discussion #8)

> ⚠️ These endpoints require authentication. Methods are inferred — verify with actual traffic capture.
