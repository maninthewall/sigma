# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke, Florian Roth, juju4

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import json
import os
import re
import json
import sys
import sigma
from .mixins import RulenameCommentMixin, MultiRuleOutputMixin
from sigma.backends.base import SingleTextQueryBackend
from sigma.backends.exceptions import NotSupportedError
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from sigma.parser.condition import ConditionOR, SigmaAggregationParser

# Sumo specifics
# https://help.sumologic.com/05Search/Search-Query-Language
# want _index or _sourceCategory for performance
# try to get most string match on first line for performance
# further sorting can be done with extra parsing
# No regex match, must use 'parse regex' https://help.sumologic.com/05Search/Search-Query-Language/01-Parse-Operators/02-Parse-Variable-Patterns-Using-Regex
# For some strings like Windows ProcessCmdline or LogonProcess, it might be good to force case lower and upper as Windows is inconsistent in logs


class SumoLogicBackend(SingleTextQueryBackend, MultiRuleOutputMixin):
    """Converts Sigma rule into SumoLogic query. Contributed by SOC Prime. https://socprime.com"""
    identifier = "sumologic"
    active = True
    config_required = False
    default_config = ["sysmon", "sumologic"]
    supported_alert_methods = {'email', 'http_post'}

    options = SingleTextQueryBackend.options + (
        ("alert_methods", "", "Alert method(s) to use when the rule triggers, comma separated. Supported: " + ', '.join(supported_alert_methods), None),

        # Options for Webhook alerting
        ("webhook_notification", False, "Use webhooks for notification", None),
        ("webhook_id", None, "Sumologic webhook ID number", None),
        ("webhook_payload", None, "Sumologic webhook payload", None),

        # Options for Email alerting
        ("email_notification", None, "Who to email", None),
        ("mute_errors", False, "Mute error emails. Default False", None),

        # Options for Index override
        ("index_field", "_index", "Index field [_index, _sourceCategory, _view]. Default _index", None),

        # Options for output
        ("output", "plain", "Output format:  json = to output in Sumologic Content API json format | plain = output query only. Default plain", None),

        # Other options
        ("timezone", "Etc/UTC", "Default timezone for search. Default Etc/UTC", None),
        ("itemize_alerts", False, "Send a separate alert for each search result. Default False", None),
        ("max_itemized_alerts", 50, "Maximum number of alerts to send for each search result. Default 50", None),
        ("minimum_interval", "15m", "Minimum interval supported for scheduled queries. Default 15m", None),
        ("use_fields", False, "Output fields command. Default False", None),
        )

    index_field = "_sourceCategory"
    reClear = None
    andToken = " AND "
    orToken = " OR "
    notToken = "!"
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "isEmpty(%s)"
    notNullExpression = "!isEmpty(%s)"
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"
    interval = None
    logname = None
    fields = None
    aggregates = list()
    whereClauses = list()

    def generateAggregation(self, agg):
        # lnx_shell_priv_esc_prep.yml
        # print("DEBUG generateAggregation(): %s, %s, %s, %s" % (agg.aggfunc_notrans, agg.aggfield, agg.groupfield, str(agg)))
        # Below we defer output of the actual aggregation commands until the rest of the query is built.
        # We do this because aggregation commands like count will cause data to be lost that isn't counted
        # and we want all search terms/query conditions processed first before we aggregate.
        if agg.groupfield == 'host':
            agg.groupfield = 'hostname'
        if agg.aggfunc_notrans == 'count() by':
            agg.aggfunc_notrans = 'count by'
        if agg.aggfunc == SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
            #agg.aggfunc_notrans = 'count'
            #current_agg = " | timeslice %s | %s by %s | where _count > 0" % (self.interval, agg.aggfunc_notrans, "_timeslice," + agg.current[0] )
            #self.aggregates.append(current_agg)
            #return ""
        if self.keypresent:
            if not agg.groupfield:
                if agg.aggfield:
                    agg.aggfunc_notrans = "count_distinct"
                    current_agg =  " \n| %s(%s) \n| where _count_distinct %s %s" % (
                        agg.aggfunc_notrans, agg.aggfield, agg.cond_op, agg.condition)
                    self.aggregates.append(current_agg)
                    return ""
                else:
                    current_agg = "  \n| %s | where _count %s %s" % (
                        agg.aggfunc_notrans, agg.cond_op, agg.condition)
                    self.aggregates.append(current_agg)
                    return ""
            elif agg.groupfield:
                if agg.aggfield:
                    agg.aggfunc_notrans = "count_distinct"
                    current_agg = " \n| %s(%s) by %s \n| where _count_distinct %s %s" % (
                        agg.aggfunc_notrans, agg.aggfield, agg.groupfield, agg.cond_op, agg.condition)
                    self.aggregates.append(current_agg)
                    return ""
                else:
                    current_agg = " \n| %s by %s \n| where _count %s %s" % (
                        agg.aggfunc_notrans, agg.groupfield, agg.cond_op, agg.condition)
                    self.aggregates.append(current_agg)
                    return ""
            else:
                current_agg = " \n| %s | where _count %s %s" % (agg.aggfunc_notrans, agg.cond_op, agg.condition)
                self.aggregates.append(current_agg)
                return ""
        else:
            if not agg.groupfield:
                if agg.aggfield:
                    agg.aggfunc_notrans = "count_distinct"
                    return " \n| parse \"[%s=*]\" as searched nodrop\n| %s(searched) \n| where _count_distinct %s %s" % (
                        agg.aggfield, agg.aggfunc_notrans, agg.cond_op, agg.condition)
                    self.aggregates.append(current_agg)
                    return ""
                else:
                    current_agg = " \n| %s | where _count %s %s" % (
                        agg.aggfunc_notrans, agg.cond_op, agg.condition)
                    self.aggregates.append(current_agg)
                    return ""
            elif agg.groupfield:
                if agg.aggfield:
                    agg.aggfunc_notrans = "count_distinct"
                    current_agg = " \n| parse \"[%s=*]\" as searched nodrop\n| parse \"[%s=*]\" as grpd nodrop\n| %s(searched) by grpd \n| where _count_distinct %s %s" % (
                        agg.aggfield, agg.groupfield, agg.aggfunc_notrans, agg.cond_op, agg.condition)
                    self.aggregates.append(current_agg)
                    return ""
                else:
                    current_agg = " \n| parse \"[%s=*]\" as grpd nodrop\n| %s by grpd \n| where _count %s %s" % (
                        agg.groupfield, agg.aggfunc_notrans, agg.cond_op, agg.condition)
                    self.aggregates.append(current_agg)
                    return ""
            else:
                current_agg = " \n| %s | where _count %s %s" % (agg.aggfunc_notrans, agg.cond_op, agg.condition)
                self.aggregates.append(current_agg)
                return ""

    def generateBefore(self, parsed):
        # not required but makes query faster, especially if no FER or _index/_sourceCategory
        if self.logname:
            return "%s " % self.logname
        return ""

    def generate(self, sigmaparser):
        rulename = self.getRuleName(sigmaparser)
        title = sigmaparser.parsedyaml.setdefault("title", "")
        description = sigmaparser.parsedyaml.setdefault("description", "No Description")
        false_positives = sigmaparser.parsedyaml.setdefault("falsepositives", "")
        level = sigmaparser.parsedyaml.setdefault("level", "")
        rule_tag = sigmaparser.parsedyaml.setdefault("tags", ["NOT-DEF"])
        # Get time frame if exists otherwise set it to 15 minutes
        interval = sigmaparser.parsedyaml["detection"].setdefault("timeframe", "15m")

        try:
            self.product = sigmaparser.parsedyaml['logsource']['product']   # OS or Software
        except KeyError:
            self.product = None
        try:
            self.service = sigmaparser.parsedyaml['logsource']['service']   # Channel
        except KeyError:
            self.service = None
        try:
            self.category = sigmaparser.parsedyaml['logsource']['category']   # Channel
        except KeyError:
            self.category = None
        # FIXME! don't get backend config mapping
        self.indices = sigmaparser.get_logsource().index
        if len(self.indices) == 0:
            self.indices = None
        try:
            self.interval = sigmaparser.parsedyaml['detection']['timeframe']
        except:
            pass

        result = ""

        # Build the content for the fields command based on the fields listed in the Rule
        columns = list()
        try:
            for field in sigmaparser.parsedyaml["fields"]:
                mapped = sigmaparser.config.get_fieldmapping(field).resolve_fieldname(field, sigmaparser)
                if type(mapped) == str:
                    columns.append(mapped)
                elif type(mapped) == list:
                    columns.extend(mapped)
                else:
                    raise TypeError("Field mapping must return string or list")
        except KeyError:    # no 'fields' attribute
            pass

        # Create the fields command for us to potentially append later
        if columns:
            self.fields = " | fields " + ",".join(columns)


        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            # FIXME! exclude if expression is regexp but anyway, not directly supported.
            #   Not doing if aggregation ('| count') or key ('=')
            if not (query.startswith('"') and query.endswith('"')) and not (query.startswith('(') and \
               query.endswith(')')) and  not ('|' in query) and not ('=' in query):
                query = '"%s"' % query

            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            if before is not None and before is not "":
                result = before
            if query is not None:
                if result is not "":
                    result += " OR " + query
                else:
                    result = query
            if after is not None:
                result += after

        self.queries[rulename] = dict()
        self.queries[rulename]['name'] = rulename
        self.queries[rulename]['description'] = description if description else "No Description"
        self.queries[rulename]['title'] = title
        self.queries[rulename]['interval'] = self.interval

        # adding parenthesis here in case 2 rules are aggregated together - ex: win_possible_applocker_bypass
        # but does not work if count, where or other piped statements...

        if '|' in result:
            self.queries[rulename]['query'] = result
        else:
            self.queries[rulename]['query'] = '('+ result + ')'

        # output any "| where" clauses we may have created through regular expressions
        if self.whereClauses:
            self.queries[rulename]['query'] = self.queries[rulename]['query'] + " | where " + " OR ".join(self.whereClauses)
            self.whereClauses.clear()

        # if fields are specified
        # output them using the Sumologic 'fields' commmand at the end of the current query
        # if there are aggregates, dont output this field because it may cause data that is
        # needed for an aggregation to be lost
        if self.use_fields and self.fields and not self.aggregates:
            self.queries[rulename]['query'] = self.queries[rulename]['query'] + self.fields
            self.fields = None

        # if aggregates were specified
        # output them last in the query because Sumologic aggregates are lossy operations and
        # you generally want them toward the end of a query
        if self.aggregates:
            # WIP
            # Consider adding any fields listed in the 'columns' to each 'count by' commands
            # deduplicate any aggregates and preserve order
            seen = set()
            aggs = list(x for x in self.aggregates if not (x in seen or seen.add(x)))
            temp = self.queries[rulename]['query'] + "".join(aggs)
            self.queries[rulename]['query'] = temp
            self.aggregates.clear()

        # We'll output all queries in finalise()
        return

        #### commented out socprime code 
        #   # adding parenthesis here in case 2 rules are aggregated together - ex: win_possible_applocker_bypass
        #   # but does not work if count, where or other piped statements...
        #    if '|' in result:
        #        return result
        #    else:
        #        return result

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # TODO/FIXME! depending on deployment configuration, existing FER must be populate here (or backend config?)
        # aFL = ["EventID"]
        self.queries = dict()
        aFL = ["_index", "_sourceCategory", "_view", "EventID", "_sourceName", "CommandLine", "NewProcessName", "Image", "ParentImage", "ParentCommandLine", "ParentProcessName"]
        if self.sigmaconfig.config.get("afl_fields"):
            self.keypresent = True
            aFL.extend(self.sigmaconfig.config.get("afl_fields"))
        else:
            self.keypresent = False
        for item in self.sigmaconfig.fieldmappings.values():
            if item.target_type is list:
                aFL.extend(item.target)
            else:
                aFL.append(item.target)
        self.allowedFieldsList = list(set(aFL))

    # Skip logsource value from sigma document for separate path.
    # def generateCleanValueNodeLogsource(self, value):
    #    return self.valueExpression % (self.cleanValue(str(value)))

    # Clearing values from special characters.
    # Sumologic: only removing '*' (in quotes, is litteral. without, is wildcard) and '"'

    def cleanNode(self, node, key=None):
        if "*" in node and key and not re.search("[\s]", node):
            return node
        elif "*" in node and not key:
            return [x for x in node.split("*") if x]
        return node

    # Clearing values from special characters.
    def generateMapItemNode(self, node):
        key, value = node
        if key in self.allowedFieldsList:
            if key in ["_sourceCategory", "_sourceName"]:
                value = "*%s*" % value.lower()
                return self.mapExpression % (key, value)
            elif not self.mapListsSpecialHandling and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling and type(value) in (str, int):
                if key in ("LogName", "source"):
                    self.logname = value
                # need cleanValue if sigma entry with single quote
                return self.mapExpression % (key, self.cleanValue(value, key))
            elif type(value) is list:
                return self.generateMapItemListNode(key, value)
            elif type(value) == SigmaRegularExpressionModifier:
                regex = str(value)
                clause = "%s matches /%s/" % (key, self.generateValueNode(regex))
                self.whereClauses.append(clause)
                tokens = self.stripRegex(regex)
                return self.generateORNode(tokens)
            elif value is None:
                return self.nullExpression % (key, )
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))
        else:
            if not self.mapListsSpecialHandling and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling and type(value) in (str, int):
                if type(value) is str:
                    new_value = list()
                    value = self.cleanNode(value)
                    if type(value) == list:
                        new_value.append(self.andToken.join([self.cleanValue(val) for val in value]))
                    else:
                        new_value.append(value)
                    if len(new_value) == 1:
                        if self.generateANDNode(new_value):
                            return self.generateANDNode(new_value)
                        else:
                            # if after cleaning node, it is empty but there is AND statement... make it true.
                            # return "true"
                            # EXPERIMENTAL return key name in quotes instead, this *may* make better queries
                            return '"%s"' % key
                    else:
                        return self.generateORNode(new_value)
                else:
                    return self.generateValueNode(value)
            elif type(value) is list:
                new_value = list()
                for item in value:
                    item = self.cleanNode(item)
                    if type(item) is list and len(item) == 1:
                        new_value.append(item[0])
                    elif type(item) is list:
                        new_value.append(self.andToken.join([self.cleanValue(val) for val in item]))
                    else:
                        new_value.append(item)
                return self.generateORNode(new_value)
            elif type(value) == SigmaRegularExpressionModifier:
                regex = str(value)
                clause = "%s matches /%s/" % (key, self.generateValueNode(regex))
                self.whereClauses.append(clause)
                tokens = self.stripRegex(regex)
                return self.generateORNode(tokens)
            elif value is None:
                return self.nullExpression % (key, )
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

    def stripRegex(self, regex):
        regex_strings = set()
        for t in re.findall("[A-Z]{2,}(?![a-zA-Z])|[A-Z][a-zA-Z]+|[\'\w\:\$]+", regex):
            if len(t) > 2:
                regex_strings.add(t)
        return list(regex_strings)

    # from mixins.py
    # input in simple quotes are not passing through this function.
    # ex: rules/windows/sysmon/sysmon_vul_java_remote_debugging.yml, rules/apt/apt_sofacy_zebrocy.yml
    #   => OK only if field entry with list, not string
    #   => generateNode: call cleanValue
    def cleanValue(self, val, key=''):
        if isinstance(val, str):
            val = re.sub("[^\\\"](\")", "\\\"", val)
            if re.search("[\W\s]", val):# and not val.startswith('"') and not val.endswith('"'):  # or "\\" in node in [] or "/" in node:
                return self.valueExpression % val
        return val

    # for keywords values with space
    def generateValueNode(self, node, key=''):
        cV = self.cleanNode(str(node), key)
        if type(node) is int:
            return cV
        if type(cV) is list:
            return "(%s)" % "AND".join([self.cleanValue(item) for item in cV])
        if 'AND' in node and cV:
            return "(" + cV + ")"
        elif isinstance(node, str) and node.startswith('"') and node.endswith('"'):
            return cV
        else:
            return self.cleanValue(cV)

    def generateMapItemListNode(self, key, value):
        itemslist = list()
        for item in value:
            if key in self.allowedFieldsList:
                itemslist.append('%s = %s' % (key, self.generateValueNode(item, key)))
            else:
                itemslist.append('%s' % (self.generateValueNode(item)))
        return "(" + " OR ".join(itemslist) + ")"

    # generateORNode algorithm for SumoLogicBackend class.
    def generateORNode(self, node):
        if type(node) == ConditionOR and all(isinstance(item, str) for item in node):
            new_value = list()
            for value in node:
                value = self.cleanNode(value)
                if type(value) is list:
                    new_value.append(self.andToken.join([self.valueExpression % val for val in value]))
                else:
                    new_value.append(value)
            return "(" + self.orToken.join([self.generateNode(val) for val in new_value]) + ")"
        return "(" + self.orToken.join([self.generateNode(val) for val in node]) + ")"

    # generate the schedule information used in the JSON output
    def generateScheduleInfo(self, interval):
        m = re.match("(?i)(\d+)s", interval)
        if m:
            interval = self.minimum_interval

        m = re.match("(?i)(\d+)([d|h|m])", interval)
        if m:
            integer_interval = m.group(1)
            interval_type = m.group(2)
        else:
            raise NotImplementedError("interval format '%s' not supported.  format: \d[d|h|m]" % interval)

        if interval_type.lower() == "m":
            if int(integer_interval) < 15:
		        # minimum Sumologic query interval is 15 minutes
		        # raise anything less than that up to the minimum
                integer_interval = "15"
            return "0 0/%s * * * ? *" % (integer_interval), "%sMinutes" % integer_interval, "%sm" % integer_interval
        elif interval_type.lower() == "h":
            hour= "Hour"
            if int(integer_interval) > 1 and int(integer_interval) < 24:
              hour = "Hours"
            elif integer_interval == "24":
                return "0 0 12 1/1 * ? *", "1Day", "%sh" % integer_interval
            return "0 0 0/%s * * ? *" % (integer_interval), "%s%s" % (integer_interval, hour), "%sh" % integer_interval
        elif interval_type.lower() == "d":
            return "0 0 12 ? * 1,2,3,4,5,6,7", "1Day", "%sd" % integer_interval


    def finalize(self):
        result = list()
        titles = set()

        # similar to mixins.py method for creating unique rule ids, this time we do it titles
        def getTitle(title):
            title = title.replace('\n','')
            if title in titles:   # add counter if name collides
                cnt = 2
                while "%s-%d" % (title, cnt) in titles:
                    cnt += 1
                title = "%s-%d" % (title, cnt)
            titles.add(title)
            return title

        if self.webhook_notification:
            notification = {
                "taskType": "WebhookSearchNotificationSyncDefinition",
                "webhookId": self.webhook_id,
                "payload": self.webhook_payload,
                "itemizeAlerts": self.itemize_alerts,
                "maxItemizedAlerts": self.max_itemized_alerts
            }
        elif self.email_notification:
            notification = {
                "taskType": "EmailSearchNotificationSyncDefinition",
                "toList": [
                    "{to}"
                ],
                "subjectTemplate": "Search Results: {{SearchName}}",
                "includeQuery": True,
                "includeResultSet": True,
                "includeHistogram": True,
                "includeCsvAttachment": True,
            }

        for key, value in self.queries.items():
            rulename = getTitle(value['title'])
            query = value['query'].replace('\n','')
            description = value['description'].replace('\n','')
            interval = value['interval']

            cronExpression, scheduleType, scheduledInterval = self.generateScheduleInfo(interval)

            if self.output == 'json':
                format_output =  {
                    "type": "SavedSearchWithScheduleSyncDefinition",
                    "name": rulename,
                    "description": description,
                    "search": {
                        "queryText": query,
                        "defaultTimeRange": "-%s" % scheduledInterval,
                        "byReceiptTime": False,
                        "viewName": "",
                        "viewStartTime": "1970-01-01T00:00:00Z",
                        "queryParameters": [],
                        "parsingMode": "AutoParse"
                    },
                    "searchSchedule": {
                        "cronExpression": cronExpression,
                        "displayableTimeRange": "-%s" % scheduledInterval,
                        "parseableTimeRange": {
                            "type": "BeginBoundedTimeRange",
                            "from": {
                                "relativeTime": "-%s" % scheduledInterval,
                                "type": "RelativeTimeRangeBoundary"
                            },
                            "to": None,
                        },
                        "notification": None,
                        "timeZone": self.timezone,
                        "threshold": {
                            "thresholdType": "group",
                            "operator": "gt",
                            "count": 0
                        },
                        "muteErrorEmails": self.mute_errors,
                        "scheduleType": scheduleType,
                        "parameters": []
                    }
                }
                format_output['searchSchedule']['notification'] = notification
                result.append(json.dumps(format_output, indent=4))
            elif self.output == 'plain':
                result.append(query)
            else:
                raise NotImplementedError("Output type '%s' not supported" % self.output_type)

        return '\n'.join(result)

class SumoLogicCSE(SumoLogicBackend):
    """Converts Sigma rule into SumoLogic CSE query. Contributed by SOC Prime. https://socprime.com"""
    identifier = "sumologic-cse"
    active = True
    config_required = False
    default_config = ["sysmon"]

    index_field = "metdata_product"
    reClear = None
    #reEscape = re.compile('[\\\\"]')
    andToken = " and "
    orToken = " or "
    notToken = "!"
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "isEmpty(%s)"
    notNullExpression = "!isEmpty(%s)"
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"
    interval = None
    logname = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.allowedFieldsList.extend(["metdata_product", "metdata_vendor"])

    def cleanValue(self, val, key=''):
        if key == 'metadata_deviceEventId' or isinstance(val, int) or val.isdigit():
            return val
        return self.valueExpression % val

    def cleanNode(self, node, key=None):
        return node

    # Clearing values from special characters.
    def generateMapItemNode(self, node):
        key, value = node
        if key:
            if not self.mapListsSpecialHandling and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling and type(value) in (str, int):
                if key in ("LogName", "source"):
                    self.logname = value
                # need cleanValue if sigma entry with single quote
                return self.mapExpression % (key, self.cleanValue(value, key))
            elif type(value) is list:
                return self.generateMapItemListNode(key, value)
            elif value is None:
                return self.nullExpression % (key,)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))
        raise TypeError("Backend does not support query without key.")

    def generateMapItemListNode(self, key, value):
        if len(value) == 1:
            return self.mapExpression % (key, value[0])
        return "%s IN (%s)" % (key, ", ".join([self.cleanValue(item, key) for item in value]))


class SumoLogicCSERule(SumoLogicCSE):
    """Converts Sigma rule into SumoLogic CSE query"""
    identifier = "sumologic-cse-rule"
    active = True

    def __init__(self, *args, **kwargs):
        """Initialize field mappings"""
        super().__init__(*args, **kwargs)
        self.techniques = self._load_mitre_file("techniques")
        self.allowedCategories = ["Threat Intelligence", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
                                  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection",
                                  "Command and Control", "Exfiltration", "Impact"]
        self.defaultCategory = "Unknown/Other"
        self.results = []

    def find_technique(self, key_ids):
        for key_id in set(key_ids):
            if not key_id:
                continue
            for technique in self.techniques:
                if key_id == technique.get("technique_id", ""):
                    yield technique

    def _load_mitre_file(self, mitre_type):
        try:
            backend_dir = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config", "mitre"))
            path = os.path.join(backend_dir, "{}.json".format(mitre_type))
            with open(path) as config_file:
                config = json.load(config_file)
                return config
        except (IOError, OSError) as e:
            print("Failed to open {} configuration file '%s': %s".format(path, str(e)), file=sys.stderr)
            return []
        except json.JSONDecodeError as e:
            print("Failed to parse {} configuration file '%s' as valid YAML: %s" % (path, str(e)), file=sys.stderr)
            return []

    def skip_tactics_or_techniques(self, src_technics, src_tactics):
        tactics = set()
        technics = set()

        local_storage_techniques = {item["technique_id"]: item for item in self.find_technique(src_technics)}

        for key_id in src_technics:
            src_tactic = local_storage_techniques.get(key_id, {}).get("tactic")
            if not src_tactic:
                continue
            src_tactic = set(src_tactic)

            for item in src_tactics:
                if item in src_tactic:
                    technics.add(key_id)
                    tactics.add(item)

        return sorted(tactics), sorted(technics)

    def parse_severity(self, old_severity):
        if old_severity.lower() == "critical":
            return "high"
        return old_severity

    def get_tactics_and_techniques(self, tags):
        tactics = list()
        technics = list()

        for tag in tags:
            tag = tag.replace("attack.", "")
            if re.match("[t][0-9]{4}", tag, re.IGNORECASE):
                technics.append(tag.title())
            elif re.match("[s][0-9]{4}", tag, re.IGNORECASE):
                continue
            else:
                if "_" in tag:
                    tag = tag.replace("_", " ")
                tag = tag.title()
                tactics.append(tag)

        return tactics, technics

    def map_risk_score(self, level):
        if level == "critical":
            return 5
        elif level == "high":
            return 4
        elif level == "medium":
            return 3
        elif level == "low":
            return 2
        return 1

    def create_rule(self, config):
        tags = config.get("tags", [])

        tactics, technics = self.get_tactics_and_techniques(tags)
        tactics, technics = self.skip_tactics_or_techniques(technics, tactics)
        tactics = list(map(lambda s: s.replace(" ", ""), tactics))
        score = self.map_risk_score(config.get("level", "medium"))
        rule = {
            "name": "{} by {}".format(config.get("title"), config.get('author')),
            "description": "{} {}".format(config.get("description"), "Technique: {}.".format(",".join(technics))),
            "enabled": True,
            "expression": """{}""".format(config.get("translation", "")),
            "assetField": "device_hostname",
            "score": score,
            "stream": "record"
        }
        if tactics and tactics[0] in self.allowedCategories:
            rule.update({"category": tactics[0]})
        else:
            rule.update({"category": "Unknown/Other"})
        self.results.append(rule)
        #return json.dumps(rule, indent=4, sort_keys=False)

    def generate(self, sigmaparser):
        translation = super().generate(sigmaparser)
        if translation:
            configs = sigmaparser.parsedyaml
            configs.update({"translation": translation})
            rule = self.create_rule(configs)
            return rule
        else:
            raise NotSupportedError("No table could be determined from Sigma rule")

    def finalize(self):
        if len(self.results) == 1:
           return json.dumps(self.results[0], indent=4, sort_keys=False)
        elif len(self.results) > 1:
            return json.dumps(self.results, indent=4, sort_keys=False)



