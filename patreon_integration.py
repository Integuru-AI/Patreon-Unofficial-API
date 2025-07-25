import json
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

import aiohttp
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from submodule_integrations.models.integration import Integration
from submodule_integrations.utils.errors import IntegrationAuthError, IntegrationAPIError


class SwitchCredentials(BaseModel):
    old_password: str
    new_password: Optional[str] = None
    new_email: Optional[str] = None


class PatreonIntegration(Integration):
    def __init__(self, token: str, network_requester=None, user_agent: str = UserAgent().random):
        super().__init__("patreon")
        self.token = token
        self.network_requester = network_requester
        self.user_agent = user_agent
        self.url = "https://www.patreon.com"

        self.headers = {
            "Host": "www.patreon.com",
            "User-Agent": self.user_agent,
            "Cookie": token
        }

    async def _make_request(
            self, method: str, url: str, **kwargs
    ) -> dict | str | bytes:
        if self.network_requester is not None:
            response = await self.network_requester.request(
                method, url, process_response=self._handle_response, **kwargs
            )
            return response
        else:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url, **kwargs) as response:
                    return await self._handle_response(response)

    async def _handle_response(self, response: aiohttp.ClientResponse):
        if response.status == 200:
            try:
                data = await response.json()
            except (json.decoder.JSONDecodeError, aiohttp.ContentTypeError):
                data = await response.text()

            return data

        if response.status == 204:
            return "Successful"

        print(await response.text())
        if response.status == 401:
            raise IntegrationAuthError(
                "Patreon: Auth failed",
                response.status,
            )
        else:
            raise IntegrationAPIError(
                self.integration_name,
                "Internal Server Error",
                500,
                response.reason,
            )

    async def member_activity_data_by_tier(self):
        path = self.url + "/api/creator-analytics/membership-growth"
        params = {
            "aggperiod": "MONTH",
            "fetch_percent_change": "true",
            "aggregateby": "tier_id",
            "json-api-version": "1.0",
            "json-api-use-default-includes": "false",
            "include": "[]"
        }

        response = await self._make_request(method="GET", url=path, params=params, headers=self.headers)
        analytics = self._parse_membership_analytics(response)
        paid_free_res = self._get_paid_vs_free_summary(analytics)
        return {
            "analytics": analytics,
            "summary": paid_free_res
        }

    @staticmethod
    def _parse_membership_analytics(response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse membership analytics response data.

        Args:
            response_data (dict): The JSON response from the membership analytics endpoint

        Returns:
            dict: Parsed data structure with overall metrics, tier breakdowns, and timestamps
        """

        # Extract the main data and tiers from the response
        attributes = response_data.get('data', {}).get('attributes', {})
        data = attributes.get('data', {})
        tiers_info = attributes.get('tiers', [])

        # Create tier lookup for easy reference
        tier_lookup = {str(tier['id']): tier for tier in tiers_info}

        # Initialize result structure
        result = {
            'overall_metrics': {},
            'tier_breakdown': {},
            'timestamps': [],
            'tier_definitions': tier_lookup,
            'last_updated_at': data.get('last_updated_at'),
            'response_type': 'overall' if '_keys' in data and len(data.get('_keys', [])) == 1 else 'by_tier'
        }

        # Extract timestamps from the data keys
        timestamps = []
        if '_keys' in data:
            timestamps = [ts for ts in data['_keys'] if ts.isdigit()]

        # If this is an overall response (single key like "1")
        if result['response_type'] == 'overall':
            # Extract overall metrics from root level
            for key, value in data.items():
                if key.startswith(('sum_', 'cumulative_sum_')) and not key.endswith('_keys'):
                    result['overall_metrics'][key] = value

            # Get timestamps from nested structure if available
            main_key = data.get('_keys', [None])[0]
            if main_key and main_key in data:
                nested_data = data[main_key]
                if '_keys' in nested_data:
                    timestamps = [ts for ts in nested_data['_keys'] if ts.isdigit()]

                    # Extract time-series data
                    time_series = {}
                    for ts in timestamps:
                        if ts in nested_data:
                            time_series[ts] = {k: v for k, v in nested_data[ts].items()
                                               if k.startswith(('sum_', 'cumulative_sum_'))}
                    result['time_series'] = time_series

        # If this is a tier breakdown response
        else:
            # Extract overall metrics from root level
            for key, value in data.items():
                if key.startswith(('sum_', 'cumulative_sum_')) and not key.endswith('_keys'):
                    result['overall_metrics'][key] = value

            # Extract tier-specific data
            tier_keys = [k for k in data.get('_keys', []) if k.isdigit() and k in tier_lookup]

            for tier_id in tier_keys:
                if tier_id in data:
                    tier_data = data[tier_id]
                    tier_info = tier_lookup.get(tier_id, {})

                    # Extract tier metrics
                    tier_metrics = {}
                    for key, value in tier_data.items():
                        if key.startswith(('sum_', 'cumulative_sum_')) and not key.endswith('_keys'):
                            tier_metrics[key] = value

                    # Extract time-series data for this tier
                    tier_timestamps = tier_data.get('_keys', [])
                    time_series = {}
                    for ts in tier_timestamps:
                        if ts.isdigit() and ts in tier_data:
                            time_series[ts] = {k: v for k, v in tier_data[ts].items()
                                               if k.startswith(('sum_', 'cumulative_sum_'))}

                    result['tier_breakdown'][tier_id] = {
                        'tier_info': tier_info,
                        'metrics': tier_metrics,
                        'time_series': time_series
                    }

                    # Collect all timestamps
                    timestamps.extend(tier_timestamps)

        # Remove duplicates and sort timestamps
        result['timestamps'] = sorted(list(set(ts for ts in timestamps if ts.isdigit())))

        # Add convenience methods for common queries
        result['paid_tiers'] = [tid for tid, info in tier_lookup.items()
                                if not info.get('is_free_tier', False)]
        result['free_tiers'] = [tid for tid, info in tier_lookup.items()
                                if info.get('is_free_tier', False)]

        return result

    @staticmethod
    def _get_paid_vs_free_summary(parsed_data):
        """
        Helper function to summarize paid vs free membership data.

        Args:
            parsed_data (dict): Output from parse_membership_analytics()

        Returns:
            dict: Summary of paid vs free metrics
        """
        summary = {
            'paid': {'active_pledges': 0, 'created_pledges': 0},
            'free': {'active_pledges': 0, 'created_pledges': 0},
            'total': parsed_data.get('overall_metrics', {})
        }

        if parsed_data['response_type'] == 'by_tier':
            for tier_id, tier_data in parsed_data['tier_breakdown'].items():
                tier_info = tier_data.get('tier_info', {})
                metrics = tier_data.get('metrics', {})

                target = 'free' if tier_info.get('is_free_tier', False) else 'paid'
                summary[target]['active_pledges'] += metrics.get('sum_num_active_pledges', 0)
                summary[target]['created_pledges'] += metrics.get('sum_num_created_pledges', 0)

        return summary

    async def member_activity_data_by_billing(self):
        path = self.url + "/api/creator-analytics/membership-growth"
        params = {
            "aggperiod": "MONTH",
            "fetch_percent_change": "true",
            "aggregateby": "charge_cadence_months",
            "json-api-version": "1.0",
            "json-api-use-default-includes": "false",
            "include": "[]"
        }

        response = await self._make_request(method="GET", url=path, params=params, headers=self.headers)
        analytics = self._parse_membership_analytics(response)
        paid_free_res = self._get_paid_vs_free_summary(analytics)
        return {
            "analytics": analytics,
            "summary": paid_free_res
        }

    async def fetch_tier_upgrades_downgrades(self):
        path = self.url + "/api/creator-analytics/tier-upgrades-downgrades"
        params = {
            "aggperiod": "MONTH",
            "include_free_tier": "false",
            "aggregateby": "tier_id",
            "range": "1y",
            "json-api-version": "1.0",
            "json-api-use-default-includes": "false",
            "include": "[]"
        }

        response = await self._make_request(method="GET", url=path, params=params, headers=self.headers)
        denormalized_data = self._denormalize_tier_upgrades_downgrades(response)
        return denormalized_data

    @staticmethod
    def _denormalize_tier_upgrades_downgrades(response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Denormalize tier upgrades/downgrades response data into a more accessible format.

        Args:
            response_data (dict): The JSON response from the tier-upgrades-downgrades endpoint

        Returns:
            dict: Denormalized data with time series and tier information
        """
        # Extract the main data structures
        attributes = response_data.get('data', {}).get('attributes', {})
        data = attributes.get('data', {})
        tiers = attributes.get('tiers', [])

        # Create tier lookup for easy reference
        tier_lookup = {str(tier['id']): tier for tier in tiers}

        # Extract timestamps
        time_keys = [ts for ts in data.get('_keys', []) if ts.isdigit()]

        # Initialize result structure
        result = {
            'time_series': [],
            'tiers': tier_lookup,
            'overall_metrics': {},
            'last_updated_at': data.get('last_updated_at')
        }

        # Extract overall metrics
        for key, value in data.items():
            if key not in ['_keys', 'last_updated_at'] and not key.isdigit():
                result['overall_metrics'][key] = value

        # Process time series data
        for timestamp in time_keys:
            time_data = data.get(timestamp, {})
            entry = {
                'timestamp': int(timestamp),
                'datetime': datetime.fromtimestamp(int(timestamp)).isoformat(),
                'metrics': {}
            }

            # Add metrics for this timestamp
            for key, value in time_data.items():
                if key != '_keys':
                    entry['metrics'][key] = value

            result['time_series'].append(entry)

        # Sort time series by timestamp
        result['time_series'].sort(key=lambda x: x['timestamp'])

        return result

    async def fetch_earnings(self, start_date: str, end_date: str):
        campaign_id = await self._get_campaign_id()

        """Date formats should be `YYYY-MM-DD`"""

        path = f"{self.url}/api/campaigns/{campaign_id}/aggregations"
        params = {
            "range_start_date": start_date,
            "range_end_date": end_date,
            "fields[aggregation]": "interval,attempted_charge,start_date,net_earnings,patreon_fee,"
                                   "external_fee,fee_taxes,currency_conversion_fee,refunds,gross_earnings,"
                                   "take_home_earnings,merch_costs,declines,currency_code,app_store_fee,"
                                   "source_breakdown,is_partial_earnings_data,last_updated_at",
            "json-api-use-default-includes": "false",
            "filter[interval]": "month",
            "filter[earnings_type]": "total",
            "json-api-version": "1.0",
            "include": "[]"
        }

        response = await self._make_request(method="GET", url=path, params=params, headers=self.headers)
        result = self._sanitize_earnings_response(response)
        return result

    @staticmethod
    def _sanitize_earnings_response(response_data):
        """Sanitize earnings response with predictable IDs."""
        sanitized_data = []

        for item in response_data['data']:
            # Extract date from start_date for consistent ID
            start_date = item['attributes']['start_date']
            date_part = start_date[:10]

            sanitized_item = {
                'id': f"{date_part}",
                'type': item['type'],
                'attributes': item['attributes']
            }

            sanitized_data.append(sanitized_item)

        return {'data': sanitized_data}

    async def fetch_earnings_csv(self):
        path = f"{self.url}/dashboard/creator-analytics-earnings.csv"

        response = await self._make_request(method="GET", url=path, headers=self.headers)
        return response

    async def fetch_exit_surveys_csv(self):
        path = f"{self.url}/dashboard/exit-surveys.csv"

        response = await self._make_request(method="GET", url=path, headers=self.headers)
        return response

    async def fetch_traffic_data(self):
        current_date = datetime.now()
        start_date = current_date - timedelta(days=365 * 3)
        start_date_str = start_date.strftime("%Y-%m-%d")
        end_date_str = current_date.strftime("%Y-%m-%d")

        path = self.url + "/api/creator-analytics/creator-traffic-growth"
        params = {
            "timezone": "Etc/UTC",
            "aggperiod": "MONTH",
            "range_start_date": start_date_str,
            "range_end_date": end_date_str,
            "aggregateby": "source",
            "json-api-version": "1.0",
            "json-api-use-default-includes": "false",
            "include": []
        }

        response = await self._make_request(method="GET", url=path, params=params, headers=self.headers)
        denormalized_data = self._denormalize_traffic_data(response)
        return denormalized_data

    @staticmethod
    def _denormalize_traffic_data(response_data):
        """Convert nested traffic data to flat records split by source with cumulative monthly summary."""
        data = response_data['data']['attributes']
        result = {}

        for source in data['_keys']:
            if source in ['_keys', 'sum_num_distinct_traffic', 'last_updated_at']:
                continue

            records = []
            monthly_totals = defaultdict(int)
            source_data = data[source]

            for timestamp_str in source_data['_keys']:
                if timestamp_str.isdigit():
                    traffic_count = source_data[timestamp_str]['sum_num_distinct_traffic']
                    date_str = datetime.fromtimestamp(int(timestamp_str)).strftime('%Y-%m-%d')
                    month_key = date_str[:7]  # YYYY-MM

                    monthly_totals[month_key] += traffic_count

                    records.append({
                        'timestamp': int(timestamp_str),
                        'date': date_str,
                        'traffic_count': traffic_count,
                        'month': month_key,
                        'cumulative_monthly': monthly_totals[month_key]
                    })

            result[source] = records

        return result

    async def _get_campaign_id(self) -> str:
        """Get campaign ID from badges endpoint."""
        path = self.url + "/api/badges"
        params = {
            "json-api-version": "1.0",
            "json-api-use-default-includes": False,
            "include": []
        }
        params = json.dumps(params)

        response = await self._make_request(method="GET", url=path, params=params, headers=self.headers)

        # Look for campaign ID in badge data
        for badge in response.get("data", []):
            badge_id = badge.get("id", "")
            if badge_id.startswith("campaign:"):
                # Extract campaign ID from format "campaign:14056138:messages"
                return badge_id.split(":")[1]

        raise IntegrationAPIError(
            integration_name=self.integration_name,
            message="Could not find campaign ID in badges endpoint.",
            error_code="server_error",
            status_code=500,
        )

    async def change_patreon_credentials(self, request: SwitchCredentials):
        """
        Reverse engineers the process of changing credentials on Patreon.

        This method disconnects a Google account, and then optionally changes the
        email and/or password for a Patreon account.
        """
        if not request.new_email and not request.new_password:
            print("Error: You must provide a new email or a new password to change.")
            return JSONResponse(status_code=400, content={
                "message": "You must provide a new email or a new password to change."
            })

        switch_headers = self.headers.copy()
        print("Fetching CSRF token from account settings...")
        try:
            account_page_res = await self._make_request("GET", "https://www.patreon.com/settings/account",
                                                        headers=switch_headers)
            soup = BeautifulSoup(account_page_res, "html.parser")
            csrf_token_meta = soup.find("meta", {"name": "csrf-token"})
            if not csrf_token_meta or not csrf_token_meta.get("content"):
                print("Error: Could not find a valid CSRF token. Is your cookie correct?")
                return JSONResponse(status_code=500, content={
                    "message": "Something went wrong fetching CSRF token. Please re-authenticate and try again"
                })
            csrf_token = csrf_token_meta.get("content")
            switch_headers.update({"x-csrf-signature": csrf_token})
            print("Successfully retrieved CSRF token.")
        except Exception as e:
            print(f"Error fetching CSRF token: {e}")
            return JSONResponse(status_code=500, content={
                "message": "Something went wrong fetching CSRF token."
            })

        # 2. Disconnect Google Account
        print("\nAttempting to disconnect Google account...")
        disconnect_url = "https://www.patreon.com/api/user/disconnect-google?json-api-version=1.0&json-api-use-default-includes=false"
        try:
            disconnect_res = await self._make_request("POST", disconnect_url, headers=switch_headers)
            if disconnect_res == "Successful":
                print("Successfully disconnected auth service")
            else:
                print("Failed to disconnect auth service")
        except Exception as e:
            print(f"An error occurred while trying to disconnect Google: {e}")

        email_res_string = "No email provided to change."
        # 3. Change Email (if provided)
        if request.new_email:
            print("\nUpdating email address...")
            email_change_url = "https://www.patreon.com/api/current_user?include=campaign.creator.null&fields[user]=email&json-api-version=1.0"
            email_payload = {
                "data": {
                    "type": "user",
                    "attributes": {"email": request.new_email, "old_password": request.old_password},
                }
            }
            try:
                email_res = await self._make_request("PATCH", email_change_url, json=email_payload,
                                                     headers=switch_headers)
                if email_res and email_res.get("data"):
                    print(f"Successfully changed email to: {request.new_email}")
                    email_res_string = "Successfully changed email. A verification code has been sent to your inbox."
                else:
                    email_res_string = "Failed to change email."
                    print(email_res_string)
                    print(f"Response: {email_res}")
            except Exception as e:
                print(f"An error occurred during email change: {e}")
                email_res_string = "Failed to change email."

        password_res_string = "No password provided."
        # 4. Change Password (if provided)
        if request.new_password:
            print("\nUpdating password...")
            password_change_url = "https://www.patreon.com/api/settings/change-password?json-api-version=1.0"
            password_payload = {
                "data": {
                    "old_password": request.old_password,
                    "new_password": request.new_password,
                    "new_password_confirmation": request.new_password,
                }
            }
            try:
                password_res = await self._make_request("POST", password_change_url, json=password_payload,
                                                        headers=switch_headers)
                if password_res == "Successful":
                    password_res_string = "Successfully changed password."
                    print(password_res_string)
                else:
                    password_res_string = "Failed to change password."
                    print(password_res_string)
                    print(f"Response: {password_res}")
            except Exception as e:
                print(f"An error occurred during password change: {e}")
                password_res_string = "Failed to change password."

        return JSONResponse(status_code=200, content={
            "message": f"{email_res_string} {password_res_string}"
        })

    async def fetch_post_data(self, post_id: str):
        data_path = f"{self.url}/api/posts/{post_id}"
        params = {
            # Include relationships - combined from both requests, removed 'custom_thumbnail_media.null'
            "include": ",".join([
                # "access_rules.tier.null",
                "attachments.null",
                "attachments_media",
                "audio",
                # "audio_preview.null",
                # "campaign.access_rules.tier.null",
                "campaign.earnings_visibility",
                "campaign.is_nsfw",
                # "can_ask_pls_question_via_zendesk",
                "custom_thumbnail_media.null",
                "collaborations",
                "collections",
                "content_locks.null",
                "content_unlock_options.product_variant.null",
                "content_unlock_options.product_variant.insights",  # From second request
                "content_unlock_options.reward.null",
                "drop",
                "images.null",
                "moderator_actions",
                "native_video_insights",  # From second request
                "parent_highlight_post",
                "podcast",
                "poll",
                "poll.choices",
                "publish_channels",
                "rss_synced_feed",
                "shows",
                # "user.null",
                "user_defined_tags.null",
                "video"
            ]),

            # Post fields - combined from both requests, removed 'thumbnail' and 'thumbnail_position'
            "fields[post]": ",".join([
                "allow_preview_in_rss",
                "audio",  # From second request
                "category",
                "cents_pledged_at_creation",
                "change_visibility_at",
                "comment_count",
                "commenter_count",  # From second request
                "comments_write_access_level",
                "content",
                "created_at",
                # "current_user_can_delete",
                "current_user_can_view",
                "current_user_has_liked",
                "deleted_at",
                # "edit_url",
                "edited_at",
                # "embed",
                "image",
                "impression_count",  # From second request
                "insights_last_updated_at",  # From second request
                "is_automated_monthly_charge",
                "is_paid",
                "is_highlight",
                "is_preview_blurred",
                "like_count",
                "min_cents_pledged_to_view",
                "monetization_ineligibility_reason",  # From second request
                "new_post_email_type",
                "num_pushable_users",
                "patreon_url",
                "patron_count",
                "paywall_display",
                "pledge_url",
                "post_file",
                "post_metadata",
                "post_type",
                "preview_asset_type",
                "published_at",
                "scheduled_for",
                "teaser_text",
                "title",
                "url",
                "video",  # From second request
                "view_count",  # From second request
                "was_posted_by_campaign_owner",
                "video_external_upload_url",
                "moderation_status",
                # "video_preview_start_ms",
                # "video_preview_end_ms",
                # "post_level_suspension_removal_date",
                "pls_one_liners_by_category",
                # "can_ask_pls_question_via_zendesk",
                # "current_user_has_post_visibility_locked"
            ]),

            # Other entity fields - combined from both requests
            # "fields[access_rule]": "access_rule_type,amount_cents",
            "fields[reward]": "title,amount_cents,currency,patron_count,id,published,is_free_tier",
            "fields[campaign]": "can_create_paid_posts,comments_access_level,is_nsfw,offers_free_membership,default_post_price_cents",
            "fields[media]": "id,image_urls,display,download_url,metadata,closed_captions_enabled,closed_captions,size_bytes,file_name,state,media_type",
            "fields[insights]": "earnings,sales,currency_code",  # From second request
            "fields[content-unlock-option]": "content_unlock_type,reward_benefit_categories",  # Combined
            "fields[product-variant]": "price_cents,currency_code,is_hidden,published_at_datetime,orders_count,live_sale_discounted_price_cents,live_sale_discounted_price_info",
            # Combined
            "fields[podcast]": "rss_published_at",
            "fields[rss-synced-feed]": "rss_url",
            "fields[shows]": "id,title,description",  # removed 'thumbnail' from here too
            "fields[post-collaboration]": "status,collaborator_campaign_id,collaborator_name",

            # API version settings
            "json-api-version": "1.0",
            "json-api-use-default-includes": "false"
        }
        response = await self._make_request(method="GET", url=data_path, params=params, headers=self.headers)
        # if isinstance(response, dict):
        #     response.pop("included", None)
        return response
