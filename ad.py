import sys, os, time, random, string
import configparser
import logging
from logging.handlers import TimedRotatingFileHandler
import random
import string
import re
import tableauserverclient as TSC
from ldap3 import Server, Connection, SUBTREE, LEVEL, ALL_ATTRIBUTES, BASE

# Setup logging
log_path = os.path.dirname(os.path.abspath(__file__))

logger = logging.getLogger('tableau_sync')
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

fh = TimedRotatingFileHandler(os.path.join(log_path, 'tableausync.log'), when="H", interval=1, backupCount=5)
fh.setFormatter(formatter)
sh = logging.StreamHandler()
sh.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(sh)

tbl_logger = logging.getLogger('tableau')
tbl_logger.setLevel(logging.DEBUG)
file_handler = TimedRotatingFileHandler(os.path.join(log_path, 'tableausync.debug'), when="D", interval=1,
                                        backupCount=3, )
file_handler.setFormatter(formatter)
tbl_logger.addHandler(file_handler)


class AD:
    def __init__(self, ad_server, ad_user, ad_password, tableau_root_ou, users_root_ou):
        self.logger = logging.getLogger('tableau_sync.ad')
        self.tableau_root_ou = tableau_root_ou
        self.users_root_ou = users_root_ou
        try:
            server = Server(ad_server, use_ssl=True)
            self.conn = Connection(server, user=ad_user, password=ad_password, raise_exceptions=True)
            self.conn.bind()
            self.logger.info("A connection was successfully established with the {0}".format(server))

        except Exception as e:
            self.logger.debug("Failed to connect to {0}".format(server))
            self.logger.debug(e)
            sys.exit()

    def _search(self, search_base, search_filter='(objectClass=*)', search_scope=BASE, attributes=ALL_ATTRIBUTES):
        try:
            self.conn.search(search_base=search_base,
                             search_filter=search_filter,
                             search_scope=search_scope,
                             attributes=attributes)
        except Exception as e:
            self.logger.debug("The query not properly ended")
            self.logger.debug(e.message)
            sys.exit()

        return self.conn.entries

    def get_members_by_groupname(self, groupname):
        self.logger.debug("Get users form {0}".format(groupname))
        group = self.get_group_by_samaccountname(groupname)
        members = self._get_group_members(group[0].distinguishedName.value)
        return members

    def _get_group_members(self, dn, group_list=[]):
        users = []
        result = self._search(dn, '(objectClass=*)')
        self.logger.debug("Get users form {0}".format(result[0].name.value))
        if 'member' in str(result):
            for member in result[0].member:
                ad_object = self._get_object_data(member)
                if ad_object.objectCategory.value.startswith('CN=Person'):
                    if not any(user.sAMAccountName.value == ad_object.sAMAccountName.value for user in
                               users) and self._is_user_enabled(ad_object.distinguishedName.value):
                        users.append(ad_object)
                if ad_object.objectCategory.value.startswith('CN=Group') and not any(
                                ad_object.distinguishedName.value == group for group in group_list):
                    group_list.append(ad_object.distinguishedName.value)
                    [users.append(newuser) for newuser in
                     self._get_group_members(ad_object.distinguishedName.value, group_list) if
                     not any(user.sAMAccountName.value == newuser.sAMAccountName.value for user in users)]
        return users

    def _is_user_enabled(self, dn):
        current_time_stamp = int(time.time()) * 10000000 + 116444736000000000
        response = self._search(dn,
                                '(&(|(accountExpires=0)(accountExpires>={0}))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'.format(
                                    current_time_stamp), BASE, ['distinguishedName'])
        if response.__len__() != 0:
            return True
        return False

    def _get_object_data(self, dn):
        result = self._search(dn, '(objectClass=*)', BASE,
                              ['name', 'distinguishedName', 'mail', 'samaccountname', 'objectcategory',
                               'accountExpires', 'enabled', 'objectClass'])
        if result:
            return result[0]
        else:
            return result

    def get_group_by_samaccountname(self, samaccountname):
        result = self._search(self.tableau_root_ou, '(Name={0})'.format(samaccountname), SUBTREE,
                              ['distinguishedName', 'name', 'member'])
        return result

def main():
    logger.debug('Loading config...')
    config = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'tableausync.conf')
    config.read_file(open(config_path))

    config_sections = config.sections()

    do_something = config.get('Common', 'do_something')
    if do_something in ['True']:
        do_something = True
        logger.info('This is the real deal, updating data in the system')
    else:
        do_something = False
        logger.info('It is TEST RUN')

    ad_server = config.get('AD', 'server')
    ad_user = config.get('AD', 'user')
    ad_password = config.get('AD', 'password')
    tableau_root_ou = config.get('AD', 'tableau_root_ou')
    users_root_ou = config.get('AD', 'users_root_ou')
    tableau_server = config.get('Tableau', 'server')
    tableau_admin = config.get('Tableau', 'username')
    tableau_password = config.get('Tableau', 'password')

    ad = AD(ad_server, ad_user, ad_password, tableau_root_ou, users_root_ou)
    
    tableau_auth = TSC.TableauAuth(tableau_admin, tableau_password)
    tableau_server = TSC.Server(tableau_server)

    with tableau_server.auth.sign_in(tableau_auth):
        opts = TSC.RequestOptions(pagesize=1000)
        tableau_all_site_users = [user for user in TSC.Pager(tableau_server.users) if user.site_role != 'Unlicensed']
        tableau_unlicensed_users = [user for user in TSC.Pager(tableau_server.users) if user.site_role == 'Unlicensed']
            
        for group in TSC.Pager(tableau_server.groups):
            # get ad_members_set for this group
            if(not group.name == 'All Users'):
                logger.info("Getting AD Group Members for: {}".format(group.name))
                ad_members = ad.get_members_by_groupname(group.name)
                ad_members_set = set([user.sAMAccountName.value for user in ad_members])
                logger.info("AD Members #: {}".format(len(ad_members_set)))

                # get tab_members_set for this group
                logger.info("Getting Tableau Group Members for: {}".format(group.name))
                tableau_server.groups.populate_users(group, opts)
                tableau_members_set = set([user.name for user in group.users])
                logger.info("Tableau Members #: {}".format(len(tableau_members_set)))

                add_members = ad_members_set - tableau_members_set
                remove_members = tableau_members_set - ad_members_set

                logger.info("Group {} - Adding Users: {}".format(group.name, add_members))
                logger.info("Group {} - Removing Users: {}".format(group.name, remove_members))


                if do_something:
                    for new_member in add_members:
                        logger.debug("Adding user:{0}".format(new_member))
                        user_id = [user.id for user in tableau_all_site_users if user.name == new_member].pop()
                        tableau_server.groups.add_user(user_id=user_id, group_item=group)

                if do_something:
                    for old_member in remove_members:
                        logger.debug("Removing user:{0}".format(old_member))
                        user_id = [user.id for user in tableau_all_site_users if user.name == old_member][0]
                        tableau_server.groups.remove_user(user_id=user_id, group_item=group)

if __name__ == '__main__':
    sys.exit(main())
