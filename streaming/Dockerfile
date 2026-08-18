FROM apache/spark:3.5.3

# psycopg2-binary was previously pip-installed by hand into the running
# container, that install lives in the container's writable layer, so any
# `docker compose up` that recreates the container (e.g. after a config
# change) silently wipes it and the streaming job fails on the next run.
# Baking it into the image fixes that for good.
USER root
# pandas: threat_processor.py calls .toPandas() on each micro-batch before
# writing it out. The old container had this only as a side-effect of
# snowflake-connector-python's own dependencies -- now that that package is
# gone, pandas has to be listed explicitly or .toPandas() breaks.
RUN pip install --no-cache-dir psycopg2-binary pandas scikit-learn joblib
# The base image's spark user (uid 185) has /home/spark as its passwd entry
# but the image never actually creates that directory -- Ivy (spark-submit
# --packages' dependency resolver) needs a writable home to cache resolved
# jars in, and silently fails without it.
RUN mkdir -p /home/spark && chown -R spark:spark /home/spark
USER spark
