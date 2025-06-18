import json
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Any, List

import aiohttp
from fake_useragent import UserAgent

from submodule_integrations.models.integration import Integration
from submodule_integrations.utils.errors import IntegrationAuthError, IntegrationAPIError


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
