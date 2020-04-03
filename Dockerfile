FROM python:3.7.7-slim

# Create app directory
RUN mkdir -p /app/
WORKDIR /app/

# Copy files
COPY static/ ./static/
COPY custom_scripts/ ./custom_scripts/
COPY templates/ ./templates/
COPY config.json default.js mobilesecurity.py requirements.txt ./

# Create non root user
RUN useradd -c 'RMS' -d /app/ rms
RUN chown -R rms:rms /app/
USER rms
ENV HOME /app
ENV PATH $PATH:$HOME/.local/bin

# Install packages
RUN pip install gunicorn
RUN pip install -r requirements.txt

EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "2", "mobilesecurity:app"]
