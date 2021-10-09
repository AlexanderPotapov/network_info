from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.dialects import postgresql

Base = declarative_base()


def get_base():
    return Base


def setup_connection(connection_string, create_db=False):
    engine = create_postgres_pool(connection_string)
    session = sessionmaker()
    session.configure(bind=engine)

    if create_db:
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)

    return session()


def create_postgres_pool(connection_string):
    engine = create_engine(connection_string)
    return engine


class Block(Base):
    __tablename__ = 'block'
    id = Column(Integer, primary_key=True)
    inetnum = Column(postgresql.CIDR, nullable=False, index=True)  # Problem with CIDR data type restrictions
    # inetnum = Column(postgresql.INET, nullable=False, index=False)
    netname = Column(String, nullable=True, index=True)
    description = Column(String, index=True)
    country = Column(String, index=True)
    maintained_by = Column(String, index=True)
    origin = Column(String, index=True)
    created = Column(DateTime, index=True)
    last_modified = Column(DateTime, index=True)
    source = Column(String, index=True)

    def __str__(self):
        return 'inetnum: {}, netname: {}, desc: {}, country: {}, maintained: {}, origin: {}, created: {}, updated: {' \
               '}, source: {}, mail: {}'.format(
            self.inetnum, self.netname, self.description, self.country,
            self.maintained_by, self.origin, self.created, self.last_modified, self.source)

    def __repr__(self):
        return self.__str__()


class ASN(Base):
    __tablename__ = 'asn'
    id = Column(Integer, primary_key=True)
    inetnum = Column(postgresql.CIDR, nullable=False, index=True) # Problem with CIDR data type restrictions
    # inetnum = Column(postgresql.INET, nullable=True, index=False)
    asn = Column(Integer, index=True)


    def __str__(self):
        return f'inetnum: {self.inetnum}, asn: {self.asn}'

    def __repr__(self):
        return self.__str__()
